package api

import (
	"context"
	"net/http"
	"time"

	"aegis/internal/executor"
	warmpool "aegis/internal/pool"
	"aegis/internal/store"
)

func HandleHealth(pool *executor.Pool, _ *warmpool.Manager) http.HandlerFunc {
	type healthResponse struct {
		Status               string `json:"status"`
		WorkerSlotsAvailable int    `json:"worker_slots_available"`
		WorkerSlotsTotal     int    `json:"worker_slots_total"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			Status:               "ok",
			WorkerSlotsAvailable: pool.Available(),
			WorkerSlotsTotal:     pool.Capacity(),
		})
	}
}

func HandleReady(s *store.Store, pool *executor.Pool, _ *warmpool.Manager) http.HandlerFunc {
	type readyResponse struct {
		Status               string `json:"status"`
		DBOK                 bool   `json:"db_ok"`
		WorkerSlotsAvailable int    `json:"worker_slots_available"`
		WorkerSlotsTotal     int    `json:"worker_slots_total"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		dbOK := s != nil && s.PingContext(ctx) == nil
		available := pool.Available()
		ready := dbOK && available > 0
		statusCode := http.StatusOK
		status := "ready"
		if !ready {
			statusCode = http.StatusServiceUnavailable
			status = "not_ready"
		}
		writeJSON(w, statusCode, readyResponse{
			Status:               status,
			DBOK:                 dbOK,
			WorkerSlotsAvailable: available,
			WorkerSlotsTotal:     pool.Capacity(),
		})
	}
}
