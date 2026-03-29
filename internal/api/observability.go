package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"aegis/internal/executor"
	"aegis/internal/store"
)

func HandleHealth(pool *executor.Pool) http.HandlerFunc {
	type healthResponse struct {
		Status               string `json:"status"`
		WorkerSlotsAvailable int    `json:"worker_slots_available"`
		WorkerSlotsTotal     int    `json:"worker_slots_total"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(healthResponse{
			Status:               "ok",
			WorkerSlotsAvailable: pool.Available(),
			WorkerSlotsTotal:     pool.Capacity(),
		})
	}
}

func HandleReady(s *store.Store, pool *executor.Pool) http.HandlerFunc {
	type readyResponse struct {
		Status               string `json:"status"`
		DBOK                 bool   `json:"db_ok"`
		WorkerSlotsAvailable int    `json:"worker_slots_available"`
		WorkerSlotsTotal     int    `json:"worker_slots_total"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		dbOK := s.PingContext(ctx) == nil
		available := pool.Available()
		ready := dbOK && available > 0
		statusCode := http.StatusOK
		status := "ready"
		if !ready {
			statusCode = http.StatusServiceUnavailable
			status = "not_ready"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_ = json.NewEncoder(w).Encode(readyResponse{
			Status:               status,
			DBOK:                 dbOK,
			WorkerSlotsAvailable: available,
			WorkerSlotsTotal:     pool.Capacity(),
		})
	}
}
