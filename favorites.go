package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Favorite is a single saved IP:Port the user wants to quickly
// re-test later without running a full CIDR scan.
type Favorite struct {
	IP      string    `json:"ip"`
	Port    int       `json:"port"`
	AddedAt time.Time `json:"added_at"`
}

func favoritesPath(cfg *Config) string {
	return filepath.Join(cfg.OutDir, cfg.OutPrefix+"-favorites.json")
}

// loadFavorites reads the saved favorites list. A missing file is not
// an error — it just means there are no favorites yet.
func loadFavorites(cfg *Config) ([]Favorite, error) {
	b, err := os.ReadFile(favoritesPath(cfg))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var favs []Favorite
	if err := json.Unmarshal(b, &favs); err != nil {
		return nil, err
	}
	return favs, nil
}

func saveFavoritesList(cfg *Config, favs []Favorite) error {
	b, err := json.MarshalIndent(favs, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", cfg.OutDir, err)
	}
	return os.WriteFile(favoritesPath(cfg), b, 0644)
}

// addFavorite appends ip:port to the favorites list. If that exact
// ip:port is already saved, it's a no-op (no duplicates), not an error.
func addFavorite(cfg *Config, ip string, port int) error {
	favs, err := loadFavorites(cfg)
	if err != nil {
		return err
	}
	for _, f := range favs {
		if f.IP == ip && f.Port == port {
			return nil
		}
	}
	favs = append(favs, Favorite{IP: ip, Port: port, AddedAt: time.Now()})
	return saveFavoritesList(cfg, favs)
}

// removeFavoriteAt removes the favorite at the given 0-based index.
func removeFavoriteAt(cfg *Config, idx int) error {
	favs, err := loadFavorites(cfg)
	if err != nil {
		return err
	}
	if idx < 0 || idx >= len(favs) {
		return fmt.Errorf("index %d out of range (have %d favorites)", idx, len(favs))
	}
	favs = append(favs[:idx], favs[idx+1:]...)
	return saveFavoritesList(cfg, favs)
}
