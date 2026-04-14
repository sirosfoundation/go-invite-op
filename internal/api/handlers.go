package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/sirosfoundation/go-invite-op/internal/domain"
	"github.com/sirosfoundation/go-invite-op/internal/storage"
	"github.com/sirosfoundation/go-invite-op/pkg/middleware"
)

// Handlers holds dependencies for invite API handlers.
type Handlers struct {
	store  storage.Store
	logger *zap.Logger
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(store storage.Store, logger *zap.Logger) *Handlers {
	return &Handlers{
		store:  store,
		logger: logger.Named("api"),
	}
}

// RegisterRoutes registers invite management API routes.
func (h *Handlers) RegisterRoutes(rg *gin.RouterGroup) {
	invites := rg.Group("/invites")
	{
		invites.POST("", h.CreateInvite)
		invites.GET("", h.ListInvites)
		invites.GET("/:id", h.GetInvite)
		invites.PUT("/:id", h.UpdateInvite)
		invites.DELETE("/:id", h.DeleteInvite)
	}
}

// CreateInviteRequest is the request body for creating an invite.
type CreateInviteRequest struct {
	Email   string `json:"email" binding:"required"`
	Code    string `json:"code,omitempty"`
	MaxUses int    `json:"max_uses,omitempty"`
	TTLSec  int    `json:"ttl_seconds,omitempty"`
}

// InviteResponse is the API response for an invite.
type InviteResponse struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	MaxUses   int       `json:"max_uses"`
	UseCount  int       `json:"use_count"`
	ExpiresAt string    `json:"expires_at,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func inviteToResponse(inv *domain.Invite) *InviteResponse {
	resp := &InviteResponse{
		ID:        inv.ID,
		TenantID:  string(inv.TenantID),
		Email:     inv.Email,
		Code:      inv.Code,
		MaxUses:   inv.MaxUses,
		UseCount:  inv.UseCount,
		CreatedAt: inv.CreatedAt,
		UpdatedAt: inv.UpdatedAt,
	}
	if !inv.ExpiresAt.IsZero() {
		resp.ExpiresAt = inv.ExpiresAt.Format(time.RFC3339)
	}
	return resp
}

// CreateInvite creates a new invite entry.
func (h *Handlers) CreateInvite(c *gin.Context) {
	tenantID := domain.TenantID(middleware.TenantFromContext(c))
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}

	var req CreateInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	code := req.Code
	if code == "" {
		var err error
		code, err = generateCode()
		if err != nil {
			h.logger.Error("Failed to generate invite code", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
	}

	invite := &domain.Invite{
		ID:       uuid.New().String(),
		TenantID: tenantID,
		Email:    req.Email,
		Code:     code,
		MaxUses:  req.MaxUses,
	}

	if req.TTLSec > 0 {
		invite.ExpiresAt = time.Now().Add(time.Duration(req.TTLSec) * time.Second)
	}

	if err := h.store.Invites().Create(c.Request.Context(), invite); err != nil {
		if errors.Is(err, storage.ErrAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{"error": "invite already exists"})
			return
		}
		h.logger.Error("Failed to create invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusCreated, inviteToResponse(invite))
}

// ListInvites lists all invites for the tenant.
func (h *Handlers) ListInvites(c *gin.Context) {
	tenantID := domain.TenantID(middleware.TenantFromContext(c))
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant_id required"})
		return
	}

	invites, err := h.store.Invites().List(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to list invites", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	result := make([]*InviteResponse, 0, len(invites))
	for _, inv := range invites {
		result = append(result, inviteToResponse(inv))
	}

	c.JSON(http.StatusOK, result)
}

// GetInvite returns a single invite by ID.
func (h *Handlers) GetInvite(c *gin.Context) {
	tenantID := domain.TenantID(middleware.TenantFromContext(c))
	id := c.Param("id")

	invite, err := h.store.Invites().GetByID(c.Request.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "invite not found"})
			return
		}
		h.logger.Error("Failed to get invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, inviteToResponse(invite))
}

// UpdateInviteRequest is the request body for updating an invite.
type UpdateInviteRequest struct {
	Email   string `json:"email,omitempty"`
	Code    string `json:"code,omitempty"`
	MaxUses *int   `json:"max_uses,omitempty"`
	TTLSec  *int   `json:"ttl_seconds,omitempty"`
}

// UpdateInvite updates an existing invite.
func (h *Handlers) UpdateInvite(c *gin.Context) {
	tenantID := domain.TenantID(middleware.TenantFromContext(c))
	id := c.Param("id")

	invite, err := h.store.Invites().GetByID(c.Request.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "invite not found"})
			return
		}
		h.logger.Error("Failed to get invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	var req UpdateInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Email != "" {
		invite.Email = req.Email
	}
	if req.Code != "" {
		invite.Code = req.Code
	}
	if req.MaxUses != nil {
		invite.MaxUses = *req.MaxUses
	}
	if req.TTLSec != nil {
		if *req.TTLSec == 0 {
			invite.ExpiresAt = time.Time{}
		} else {
			invite.ExpiresAt = time.Now().Add(time.Duration(*req.TTLSec) * time.Second)
		}
	}

	if err := h.store.Invites().Update(c.Request.Context(), invite); err != nil {
		h.logger.Error("Failed to update invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.JSON(http.StatusOK, inviteToResponse(invite))
}

// DeleteInvite removes an invite.
func (h *Handlers) DeleteInvite(c *gin.Context) {
	tenantID := domain.TenantID(middleware.TenantFromContext(c))
	id := c.Param("id")

	if err := h.store.Invites().Delete(c.Request.Context(), tenantID, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "invite not found"})
			return
		}
		h.logger.Error("Failed to delete invite", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	c.Status(http.StatusNoContent)
}

func generateCode() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
