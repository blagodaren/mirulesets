package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/rules"
	"github.com/blagodaren/mirulesets/internal/server"
	"github.com/blagodaren/mirulesets/internal/service"
	"github.com/blagodaren/mirulesets/internal/version"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	if err := run(); err != nil {
		slog.Error("MIRulesets", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runContext(ctx)
}

func runContext(ctx context.Context) error {
	if len(os.Args) > 1 && os.Args[1] == "convert" {
		return convert(os.Args[2:])
	}
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("MIRulesets " + version.Version)
		return nil
	}
	c, err := config.Load()
	if err != nil {
		return err
	}
	svc, err := service.New(c)
	if err != nil {
		return err
	}
	handler, err := server.New(svc)
	if err != nil {
		return err
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	if svc.S3 != nil {
		checkCtx, cancelCheck := context.WithTimeout(ctx, 15*time.Second)
		checkErr := svc.S3.Check(checkCtx)
		cancelCheck()
		if checkErr != nil {
			const message = "S3 недоступен при запуске; локальная раздача работает, отправка будет повторена"
			slog.Warn(message)
			svc.Event("warning", message, "")
		}
	}
	schedulerDone := make(chan struct{})
	go func() {
		defer close(schedulerDone)
		svc.RunScheduler(ctx)
	}()
	servers := []*http.Server{}
	errs := make(chan error, 2)
	newServer := func(addr string, h http.Handler) *http.Server {
		return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 6 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	}
	switch c.TLSMode {
	case "auto":
		cache := filepath.Join(c.DataDir, "certificates")
		if err := os.MkdirAll(cache, 0700); err != nil {
			return err
		}
		manager := &autocert.Manager{Prompt: autocert.AcceptTOS, HostPolicy: autocert.HostWhitelist(c.Domain), Cache: autocert.DirCache(cache), Email: c.ACMEEmail}
		if c.ACMECA != "" {
			manager.Client = &acme.Client{DirectoryURL: c.ACMECA}
		}
		tlsServer := newServer(c.TLSAddr, handler)
		tlsServer.TLSConfig = manager.TLSConfig()
		tlsServer.TLSConfig.MinVersion = tls.VersionTLS12
		httpServer := newServer(c.HTTPAddr, manager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+c.Domain+r.URL.RequestURI(), http.StatusPermanentRedirect)
		})))
		servers = append(servers, tlsServer, httpServer)
		go func() { errs <- tlsServer.ListenAndServeTLS("", "") }()
		go func() { errs <- httpServer.ListenAndServe() }()
	case "manual":
		srv := newServer(c.TLSAddr, handler)
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		servers = append(servers, srv)
		go func() { errs <- srv.ListenAndServeTLS(c.TLSCert, c.TLSKey) }()
	default:
		srv := newServer(c.Addr, handler)
		servers = append(servers, srv)
		go func() { errs <- srv.ListenAndServe() }()
	}
	slog.Info("MIRulesets запущен", "http", c.Addr, "tls_mode", c.TLSMode, "data", c.DataDir)
	if os.Getenv("MI_ADMIN_PASSWORD") == "" && os.Getenv("MI_ADMIN_PASSWORD_FILE") == "" {
		slog.Info("Пароль администратора находится в файле", "path", filepath.Join(c.DataDir, "admin-password"))
	}
	select {
	case <-ctx.Done():
	case err = <-errs:
		stop()
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdown)
	}
	select {
	case <-schedulerDone:
	case <-shutdown.Done():
		slog.Warn("Не все плановые сборки завершились до остановки")
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func convert(args []string) error {
	f := flag.NewFlagSet("convert", flag.ContinueOnError)
	input := f.String("input", "", "входной файл")
	output := f.String("output", "", "выходной файл")
	fromFormat := f.String("from", "auto", "auto, yaml, text, mrs, hosts, adblock, geosite, geoip, singbox")
	toFormat := f.String("to", "mrs", "yaml, text, mrs, singbox, srs")
	selector := f.String("selector", "", "категории DAT через запятую или *")
	behavior := f.String("behavior", "domain", "domain, ipcidr, classical")
	target := f.String("target-behavior", "", "behavior результата (по умолчанию без изменения)")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *input == "" || *output == "" {
		return fmt.Errorf("пример: mirulesets convert -input rules.yaml -output rules.mrs -behavior domain -to mrs")
	}
	fh, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return err
	}
	if st.Size() > 32<<20 {
		return fmt.Errorf("входной файл превышает 32 MiB")
	}
	b, err := os.ReadFile(*input)
	if err != nil {
		return err
	}
	lines, err := rules.ParseSource(b, *fromFormat, *behavior, *selector)
	if err != nil {
		return err
	}
	if *target == "" {
		*target = *behavior
	}
	lines, err = rules.Transform(lines, *behavior, *target)
	if err != nil {
		return err
	}
	b, err = rules.Encode(lines, *toFormat, *target)
	if err != nil {
		return err
	}
	// O_EXCL keeps an existing destination intact; choose a new output path.
	out, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, err = out.Write(b)
	closeErr := out.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Printf("Готово: %d правил, %d байт → %s\n", len(lines), len(b), *output)
	return nil
}
