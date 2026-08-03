package encode

import (
	"fmt"
	"net/http"
)

func Attach(w http.ResponseWriter, username string, dat []byte) error {
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%s.json", username))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(dat)))
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(dat)
	return err
}
