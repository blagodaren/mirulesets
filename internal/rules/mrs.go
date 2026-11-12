package rules

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/klauspost/compress/zstd"
	"go4.org/netipx"
)

// MRS v1 wire format is documented in README.md. This implementation operates
// on the format itself and does not link to or run the Mihomo proxy engine.
const maxDecodedBytes = 64 << 20
const maxMRSNodes = 8_000_000

var mrsMagic = []byte{'M', 'R', 'S', 1}

func behaviorByte(behavior string) byte {
	if behavior == "ipcidr" {
		return 1
	}
	return 0
}

func encodeMRS(lines []string, behavior string) ([]byte, error) {
	if len(lines) == 0 {
		return nil, errors.New("в MRS нельзя записать пустой рулсет")
	}
	var body bytes.Buffer
	body.Write(mrsMagic)
	body.WriteByte(behaviorByte(behavior))
	writeInt(&body, len(lines))
	writeInt(&body, 0) // Reserved extra bytes.
	body.WriteByte(1)  // Domain set / CIDR range encoding version.
	var err error
	if behavior == "domain" {
		err = encodeDomains(&body, lines)
	} else {
		err = encodePrefixes(&body, lines)
	}
	if err != nil {
		return nil, err
	}
	if body.Len() > maxDecodedBytes {
		return nil, errors.New("распакованные данные MRS превышают 64 MiB")
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, err
	}
	defer encoder.Close()
	return encoder.EncodeAll(body.Bytes(), nil), nil
}

func writeInt(w *bytes.Buffer, value int) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	w.Write(encoded[:])
}

func writeWords(w *bytes.Buffer, words []uint64) {
	writeInt(w, len(words))
	var encoded [8]byte
	for _, word := range words {
		binary.BigEndian.PutUint64(encoded[:], word)
		w.Write(encoded[:])
	}
}

func reverseRunes(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func setWordBit(words *[]uint64, offset int) {
	for len(*words) <= offset/64 {
		*words = append(*words, 0)
	}
	(*words)[offset/64] |= uint64(1) << (offset % 64)
}

func wordBit(words []uint64, offset int) bool {
	return offset >= 0 && offset/64 < len(words) && words[offset/64]&(uint64(1)<<(offset%64)) != 0
}

func encodeDomains(w *bytes.Buffer, lines []string) error {
	keys := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "+.") {
			keys = append(keys, reverseRunes(line[2:]), reverseRunes(line))
		} else if strings.HasPrefix(line, ".") {
			keys = append(keys, reverseRunes("+"+line))
		} else {
			keys = append(keys, reverseRunes(line))
		}
	}
	sort.Strings(keys)
	unique := keys[:0]
	for _, key := range keys {
		if len(unique) == 0 || unique[len(unique)-1] != key {
			unique = append(unique, key)
		}
	}
	keys = unique
	// A node describes a contiguous range of sorted strings sharing a prefix.
	// Breadth-first traversal produces LOUDS: one zero per edge, then a one
	// ending each node. Terminal flags use the same breadth-first node order.
	type span struct{ start, end int }
	level := []span{{0, len(keys)}}
	var leaves, topology []uint64
	var labels []byte
	node, bitOffset := 0, 0
	for depth := 0; len(level) > 0; depth++ {
		next := make([]span, 0)
		for _, group := range level {
			start := group.start
			if len(keys[start]) == depth {
				setWordBit(&leaves, node)
				start++
			}
			for start < group.end {
				label := keys[start][depth]
				end := start + 1
				for end < group.end && keys[end][depth] == label {
					end++
				}
				labels = append(labels, label)
				if len(labels) >= maxMRSNodes {
					return errors.New("доменный MRS превышает лимит 8 000 000 узлов дерева")
				}
				next = append(next, span{start, end})
				bitOffset++ // Zero edge bit.
				start = end
			}
			setWordBit(&topology, bitOffset)
			bitOffset++
			node++
		}
		level = next
	}
	writeWords(w, leaves)
	writeWords(w, topology)
	writeInt(w, len(labels))
	w.Write(labels)
	return nil
}

func encodePrefixes(w *bytes.Buffer, lines []string) error {
	var builder netipx.IPSetBuilder
	for _, line := range lines {
		prefix, _ := netip.ParsePrefix(line)
		builder.AddPrefix(prefix)
	}
	set, err := builder.IPSet()
	if err != nil {
		return err
	}
	ranges := set.Ranges()
	writeInt(w, len(ranges))
	for _, item := range ranges {
		from, to := item.From().As16(), item.To().As16()
		w.Write(from[:])
		w.Write(to[:])
	}
	return nil
}

// wireReader checks remaining bytes before every allocation. A small attacker
// supplied MRS can therefore never allocate slices using untrusted int64 sizes.
type wireReader struct {
	data   []byte
	offset int
}

func (r *wireReader) take(size int) ([]byte, error) {
	if size < 0 || size > len(r.data)-r.offset {
		return nil, io.ErrUnexpectedEOF
	}
	value := r.data[r.offset : r.offset+size]
	r.offset += size
	return value, nil
}

func (r *wireReader) length(maximum int) (int, error) {
	buf, err := r.take(8)
	if err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint64(buf)
	if n > uint64(maximum) {
		return 0, fmt.Errorf("длина MRS %d превышает лимит %d", n, maximum)
	}
	return int(n), nil
}

func (r *wireReader) words(maximum int) ([]uint64, error) {
	count, err := r.length(maximum)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("пустая битовая карта MRS")
	}
	data, err := r.take(count * 8)
	if err != nil {
		return nil, err
	}
	words := make([]uint64, count)
	for i := range words {
		words[i] = binary.BigEndian.Uint64(data[i*8:])
	}
	return words, nil
}

func decodeMRS(data []byte, behavior string) ([]string, error) {
	decoder, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxDecodedBytes), zstd.WithDecoderMaxWindow(16<<20))
	if err != nil {
		return nil, fmt.Errorf("некорректное сжатие MRS: %w", err)
	}
	defer decoder.Close()
	decoded, err := io.ReadAll(io.LimitReader(decoder, maxDecodedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("некорректное сжатие MRS: %w", err)
	}
	if len(decoded) > maxDecodedBytes {
		return nil, errors.New("распакованные данные MRS превышают 64 MiB")
	}
	r := &wireReader{data: decoded}
	header, err := r.take(5)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(header[:4], mrsMagic) {
		return nil, errors.New("неверная сигнатура MRS v1")
	}
	if header[4] != behaviorByte(behavior) {
		return nil, errors.New("behavior внутри MRS не совпадает с выбранным")
	}
	count, err := r.length(MaxRules)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("нулевое количество правил в MRS")
	}
	extraLength, err := r.length(maxDecodedBytes)
	if err != nil {
		return nil, err
	}
	if _, err = r.take(extraLength); err != nil {
		return nil, err
	}
	version, err := r.take(1)
	if err != nil {
		return nil, err
	}
	if version[0] != 1 {
		return nil, errors.New("неподдерживаемая версия кодирования MRS")
	}
	var lines []string
	if behavior == "domain" {
		lines, err = decodeDomains(r)
	} else {
		lines, err = decodePrefixes(r)
	}
	if err != nil {
		return nil, fmt.Errorf("некорректные данные MRS %s: %w", behavior, err)
	}
	if r.offset != len(r.data) {
		return nil, errors.New("лишние байты в конце данных MRS")
	}
	return Normalize(lines, behavior)
}

func decodeDomains(r *wireReader) ([]string, error) {
	leaves, err := r.words((maxMRSNodes + 63) / 64)
	if err != nil {
		return nil, err
	}
	topology, err := r.words((maxMRSNodes*2 + 63) / 64)
	if err != nil {
		return nil, err
	}
	labelCount, err := r.length(maxMRSNodes - 1)
	if err != nil {
		return nil, err
	}
	if labelCount == 0 {
		return nil, errors.New("в доменном дереве нет меток")
	}
	labels, err := r.take(labelCount)
	if err != nil {
		return nil, err
	}
	nodeCount := labelCount + 1
	if len(leaves) != (nodeCount+63)/64 || len(topology) != (2*nodeCount-1+63)/64 {
		return nil, errors.New("размеры битовых карт доменного дерева не соответствуют числу меток")
	}
	if wordBit(leaves, 0) {
		return nil, errors.New("пустой домен в дереве MRS")
	}
	starts := make([]uint32, nodeCount+1)
	edge, offset := 0, 0
	for node := 0; node < nodeCount; node++ {
		starts[node] = uint32(edge)
		previousLabel := -1
		for !wordBit(topology, offset) {
			if offset >= 2*nodeCount-1 || edge >= labelCount || edge+1 <= node {
				return nil, errors.New("некорректная структура доменного дерева")
			}
			if int(labels[edge]) <= previousLabel {
				return nil, errors.New("неупорядоченные или повторяющиеся рёбра доменного дерева")
			}
			previousLabel = int(labels[edge])
			edge++
			offset++
		}
		offset++
		starts[node+1] = uint32(edge)
		if starts[node] == starts[node+1] && !wordBit(leaves, node) {
			return nil, errors.New("лист доменного дерева не содержит правила")
		}
	}
	if edge != labelCount || offset != 2*nodeCount-1 {
		return nil, errors.New("недостижимые узлы доменного дерева")
	}
	for i := nodeCount; i < len(leaves)*64; i++ {
		if wordBit(leaves, i) {
			return nil, errors.New("ненулевое заполнение битовой карты листьев")
		}
	}
	for i := offset; i < len(topology)*64; i++ {
		if wordBit(topology, i) {
			return nil, errors.New("ненулевое заполнение структуры доменного дерева")
		}
	}
	var lines []string
	path := make([]byte, 0, 128)
	totalBytes := 0
	var walk func(int) error
	walk = func(node int) error {
		if len(path) > maxDomainBytes+1 {
			return errors.New("путь доменного дерева превышает 1024 байта")
		}
		if wordBit(leaves, node) {
			if !utf8.Valid(path) {
				return errors.New("некорректный UTF-8 в доменном дереве")
			}
			line := reverseRunes(string(path))
			if strings.HasPrefix(line, "+.") {
				line = line[1:]
			}
			if _, err := normalizeDomain(line); err != nil {
				return err
			}
			lines = append(lines, line)
			totalBytes += len(line)
			if len(lines) > MaxRules*2 || totalBytes > MaxInputBytes {
				return errors.New("распакованные доменные правила превышают лимиты")
			}
		}
		for child := starts[node]; child < starts[node+1]; child++ {
			path = append(path, labels[child])
			if err := walk(int(child) + 1); err != nil {
				return err
			}
			path = path[:len(path)-1]
		}
		return nil
	}
	if err := walk(0); err != nil {
		return nil, err
	}
	// A terminal exact name plus a suffix-only name is the '+.' shorthand.
	seen := make(map[string]bool, len(lines))
	for _, line := range lines {
		seen[line] = true
	}
	compact := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, ".") && seen[line[1:]] {
			compact = append(compact, "+"+line)
		} else if !seen["."+line] {
			compact = append(compact, line)
		}
	}
	sort.Strings(compact)
	return compact, nil
}

func decodePrefixes(r *wireReader) ([]string, error) {
	count, err := r.length(MaxRules)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("пустой набор диапазонов IP")
	}
	data, err := r.take(count * 32)
	if err != nil {
		return nil, err
	}
	var lines []string
	for i := 0; i < count; i++ {
		var first, last [16]byte
		copy(first[:], data[i*32:i*32+16])
		copy(last[:], data[i*32+16:i*32+32])
		from, to := netip.AddrFrom16(first).Unmap(), netip.AddrFrom16(last).Unmap()
		ipRange := netipx.IPRangeFrom(from, to)
		if !ipRange.IsValid() {
			return nil, errors.New("некорректный диапазон IPv4/IPv6")
		}
		for _, prefix := range ipRange.Prefixes() {
			lines = append(lines, prefix.String())
			if len(lines) > MaxRules {
				return nil, errors.New("число распакованных IP-правил превышает 1 000 000")
			}
		}
	}
	return lines, nil
}
