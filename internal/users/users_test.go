package users_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ggwpLab/Jo-ei/internal/users"
)

func TestValidateUsername(t *testing.T) {
	for _, ok := range []string{"admin", "ivan.petrov", "a@b.c", "x_1-2", strings.Repeat("a", 64)} {
		assert.NoError(t, users.ValidateUsername(ok), ok)
	}
	for _, bad := range []string{"", strings.Repeat("a", 65), "ivan petrov", "ops+ci", "имя"} {
		var ve *users.ValidationError
		err := users.ValidateUsername(bad)
		assert.ErrorAs(t, err, &ve, bad)
	}
}

func TestValidatePassword(t *testing.T) {
	assert.NoError(t, users.ValidatePassword("u", strings.Repeat("я", 12)))
	assert.Error(t, users.ValidatePassword("u", strings.Repeat("я", 11)))
	assert.NoError(t, users.ValidatePassword("u", strings.Repeat("я", 36)))
	assert.Error(t, users.ValidatePassword("u", strings.Repeat("я", 37)))
	assert.NoError(t, users.ValidatePassword("u", "correcthorse"))
	assert.Error(t, users.ValidatePassword("administrator", "Administrator"))
}

func TestHashAndCheckPassword(t *testing.T) {
	h, err := users.HashPassword("correcthorse")
	assert.NoError(t, err)
	assert.True(t, users.CheckPassword(h, "correcthorse"))
	assert.False(t, users.CheckPassword(h, "wrong"))
	assert.False(t, users.CheckPassword("not-a-hash", "x"))
	assert.False(t, users.CheckPassword("", ""))
}

func TestRoleValid(t *testing.T) {
	assert.True(t, users.RoleAdmin.Valid())
	assert.True(t, users.RoleOperator.Valid())
	assert.False(t, users.Role("root").Valid())
}
