package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestPrometheusMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(PrometheusMiddleware("/health"))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Request to /test should be counted
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	count := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("GET", "/test", "200"))
	assert.Equal(t, float64(1), count)

	// Request to /health should be skipped
	w2 := httptest.NewRecorder()
	req2, _ := http.NewRequest("GET", "/health", nil)
	router.ServeHTTP(w2, req2)

	count2 := testutil.ToFloat64(httpRequestsTotal.WithLabelValues("GET", "/health", "200"))
	assert.Equal(t, float64(0), count2)
}
