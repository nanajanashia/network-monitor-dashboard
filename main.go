package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

//go:embed templates
var templateFS embed.FS

var db *sql.DB

type PacketInfo struct {
	ID             int       `json:"id"`
	Version        string    `json:"version"`
	TotalLength    int       `json:"total_length"`
	Flags          string    `json:"flags"`
	TTL            int       `json:"ttl"`
	Protocol       string    `json:"protocol"`
	HeaderChecksum int       `json:"header_checksum"`
	SourceIP       string    `json:"source_ip"`
	DestinationIP  string    `json:"destination_ip"`
	Malicious      int       `json:"malicious"`
	Suspicious     int       `json:"suspicious"`
	Harmless       int       `json:"harmless"`
	Undetected     int       `json:"undetected"`
	ScanDate       string    `json:"scan_date"`
	CheckedAt      time.Time `json:"checked_at"`
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	db = connectDB()
	defer db.Close()

	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/api/packets", handlePacketsAPI)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server starting on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func connectDB() *sql.DB {
	dbURL := os.Getenv("DB_URL")
	database, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Error opening database: ", err)
	}

	if err := database.Ping(); err != nil {
		log.Fatal("Error connecting to database: ", err)
	}

	return database
}

func getPackets(afterID int, limit int) ([]PacketInfo, error) {
	query := `
		SELECT id, version, total_length, flags, ttl, protocol, header_checksum,
		       source_ip, destination_ip, malicious, suspicious, harmless,
		       undetected, scan_date, checked_at
		FROM packet_info
		WHERE id > $1
		ORDER BY id DESC
		LIMIT $2
	`

	rows, err := db.Query(query, afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var packets []PacketInfo
	for rows.Next() {
		var p PacketInfo
		var scanDate sql.NullTime
		var flags sql.NullString

		err := rows.Scan(
			&p.ID, &p.Version, &p.TotalLength, &flags, &p.TTL, &p.Protocol,
			&p.HeaderChecksum, &p.SourceIP, &p.DestinationIP, &p.Malicious,
			&p.Suspicious, &p.Harmless, &p.Undetected, &scanDate, &p.CheckedAt,
		)
		if err != nil {
			return nil, err
		}

		if flags.Valid {
			p.Flags = flags.String
		}
		if scanDate.Valid {
			p.ScanDate = scanDate.Time.Format("2006-01-02")
		}

		packets = append(packets, p)
	}

	return packets, nil
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFS(templateFS, "templates/dashboard.html")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Printf("Template error: %v", err)
		return
	}

	packets, err := getPackets(0, 1000)
	if err != nil {
		http.Error(w, "Error fetching data", http.StatusInternalServerError)
		log.Printf("Database error: %v", err)
		return
	}

	tmpl.Execute(w, packets)
}

func handlePacketsAPI(w http.ResponseWriter, r *http.Request) {
	afterID := 0
	if idStr := r.URL.Query().Get("after_id"); idStr != "" {
		if id, err := strconv.Atoi(idStr); err == nil {
			afterID = id
		}
	}

	packets, err := getPackets(afterID, 1000)
	if err != nil {
		http.Error(w, "Error fetching data", http.StatusInternalServerError)
		log.Printf("Database error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(packets)
}
