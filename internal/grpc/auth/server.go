package auth

import (
	"context"
	"time"

	"github.com/dgrijalva/jwt-go"
	ssov1 "github.com/sssttormy/proto/gen/go/sso"
	"google.golang.org/grpc"
)

type serverAPI struct {
	ssov1.UnimplementedAuthServer
}

func (s *serverAPI) Login(ctx context.Context, r *ssov1.LoginRequest,
) (*ssov1.LoginResponse, error) {
	token, err := generateToken(r.Email, r.Password)
	if err != nil {
		return &ssov1.LoginResponse{}, err
	}
	return &ssov1.LoginResponse{
		Token: token,
	}, nil
}

func generateToken(email, password string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = email
	claims["password"] = password
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expires in 24 hours

	// Sign the token with a secret key
	secretKey := []byte("your_secret_key")
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func Register(gRPC *grpc.Server) {
	ssov1.RegisterAuthServer(gRPC, &serverAPI{})
}
