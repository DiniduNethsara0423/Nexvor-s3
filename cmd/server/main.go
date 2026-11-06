package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"my-s3/internal/api"
	"my-s3/internal/auth"
	"my-s3/internal/storage"
	"my-s3/internal/web"
)

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func getEnvAny(keys []string, fallback string) string {
	for _, k := range keys {
		if val := os.Getenv(k); val != "" {
			return val
		}
	}
	return fallback
}

func main() {
	s3Port := flag.String("port", getEnv("S3_PORT", "9000"), "Port for S3 REST API")
	consolePort := flag.String("console-port", getEnv("CONSOLE_PORT", "9001"), "Port for Web Console UI")
	dataDir := flag.String("data", getEnv("DATA_DIR", "./data"), "Directory to store bucket data")
	accessKey := flag.String("access-key", getEnvAny([]string{"NEXVOR_ROOT_USER", "MINIO_ROOT_USER", "AWS_ACCESS_KEY_ID", "ACCESS_KEY"}, "minioadmin"), "S3 Root Access Key / Username")
	secretKey := flag.String("secret-key", getEnvAny([]string{"NEXVOR_ROOT_PASSWORD", "MINIO_ROOT_PASSWORD", "AWS_SECRET_ACCESS_KEY", "SECRET_KEY"}, "minioadmin"), "S3 Root Secret Key / Password")
	allowAnon := flag.Bool("allow-anon", true, "Allow anonymous reads and unauthenticated dev requests")
	webhookURL := flag.String("webhook", getEnv("WEBHOOK_URL", ""), "Webhook URL for S3 ObjectCreated events (e.g. video transcode)")
	flag.Parse()

	// 1. Initialize Storage Engine
	diskEngine, err := storage.NewDiskEngine(*dataDir)
	if err != nil {
		log.Fatalf("Fatal: failed to initialize storage engine: %v", err)
	}

	// 2. Initialize Authentication
	authenticator := auth.NewAuthenticator(*accessKey, *secretKey, *allowAnon)

	// 3. S3 API Server (Hardened against Slowloris & DoS attacks)
	s3Handler := api.NewS3Handler(diskEngine, authenticator, *webhookURL, *consolePort)
	s3Server := &http.Server{
		Addr:              ":" + *s3Port,
		Handler:           s3Handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB max header guard
	}

	// 4. Web Console UI Server
	consoleHandler := web.NewConsoleHandler(diskEngine, *accessKey, *secretKey, *s3Port)
	consoleServer := &http.Server{
		Addr:              ":" + *consolePort,
		Handler:           consoleHandler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Banner
	fmt.Print(`
  _   _                                _____ ____  
 | \ | | _____  ___   _____  _ __     / ____|___ \ 
 |  \| |/ _ \ \/ /\ \ / / _ \| '__|   \___ \ __) | 
 | |\  |  __/>  <  \ V / (_) | |       ___) / __/  
 |_| \_|\___/_/\_\  \_/ \___/|_|      |____/_____| 
                                                   
  NexvorS3 by NexvorCodeLabs | High-Performance Object Store
`)
	fmt.Printf(" [✓] S3 API Endpoint:      http://localhost:%s\n", *s3Port)
	fmt.Printf(" [✓] Web Console UI:       http://localhost:%s\n", *consolePort)
	fmt.Printf(" [✓] Data Directory:       %s\n", *dataDir)
	fmt.Printf(" [✓] Access Key:           %s\n", *accessKey)
	fmt.Printf(" [✓] Secret Key:           %s\n", *secretKey)
	fmt.Println(" -------------------------------------------------------------")

	// Start servers
	go func() {
		log.Printf("Starting S3 REST engine on port :%s...", *s3Port)
		if err := s3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("S3 server error: %v", err)
		}
	}()

	go func() {
		log.Printf("Starting Web Console on port :%s...", *consolePort)
		if err := consoleServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Console server error: %v", err)
		}
	}()

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("\nShutting down servers gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = s3Server.Shutdown(ctx)
	_ = consoleServer.Shutdown(ctx)
	log.Println("My-S3 exited cleanly.")
}
