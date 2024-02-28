package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
	"unicode/utf8"
)

const (
	Port        = "9090"
	SafeMode    = false
	MessageRate = 1.0
	StrikeLimit = 3
	BanLimit    = 5 * 60 // minutes
	BufSize     = 32
)

func sensitive(msg string) string {
	if SafeMode {
		return "[REDACTED]"
	}
	return msg
}

type MessageType int

const (
	ClientConnected MessageType = iota + 1
	NewMessage
	ClientDisconnected
)

type Message struct {
	Type MessageType
	Conn net.Conn
	Text string
}

type Client struct {
	Conn        net.Conn
	LastMessage time.Time
	StrikeCount int
}

func authorized(conn net.Conn, token string) error {
	buffer := make([]byte, BufSize*2)
	n, err := conn.Read(buffer)

	switch {
	case n < len(buffer):
		return errors.New(fmt.Sprintf("Incomplete read of token: %v/%v\n", n, len(buffer)))
	case !utf8.Valid(buffer):
		return errors.New(fmt.Sprintf("Token is not a valid UTF8 string: %v\n", err))
	case token != string(buffer):
		return errors.New("User provided an invalid token")
	default:
		return err
	}
}

func client(conn net.Conn, ch chan Message, token string) {
	clientAddr := conn.RemoteAddr()
	if clientAddr == nil {
		slog.Error("Could not get address from sender\n")
		conn.Close()
		return
	}

	// ask for auth token
	_, err := conn.Write([]byte("Token: "))
	if err != nil {
		slog.Info(
			fmt.Sprintf("Could not send Token prompt to %v: %v\n",
				sensitive(clientAddr.String()),
				sensitive(err.Error())))
		conn.Close()
		return
	}

	// authorization guard
	if err := authorized(conn, token); err != nil {
		slog.Error(
			fmt.Sprintf("Reading authorization token from %v: %v\n",
				sensitive(clientAddr.String()),
				sensitive(err.Error())))

		// tell user about error
		_, err = conn.Write([]byte("Invalid authorization token\n"))
		if err != nil {
			slog.Info(
				fmt.Sprintf("Could not notify client %v about invalid token: %v\n",
					sensitive(clientAddr.String()),
					sensitive(err.Error())))
		}

		conn.Close()
		return
	}

	slog.Info(fmt.Sprintf("%v is authorized!", sensitive(clientAddr.String())))
	_, err = conn.Write([]byte("Welcome to Chatti!\n"))
	if err != nil {
		slog.Info(
			fmt.Sprintf("Could not greet client %v: %v\n",
				sensitive(clientAddr.String()),
				sensitive(err.Error())))
	}

	ch <- Message{
		Type: ClientConnected,
		Conn: conn,
	}

	buffer := make([]byte, 512)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			conn.Close()
			ch <- Message{
				Type: ClientDisconnected,
				Conn: conn,
			}
			return
		}

		text := string(buffer[0:n])
		ch <- Message{
			Type: NewMessage,
			Conn: conn,
			Text: text,
		}
	}
}

func server(ch chan Message) {
	clients := make(map[string]*Client)
	bannedMfs := make(map[string]time.Time)
	for {
		msg := <-ch
		switch msg.Type {

		case ClientConnected:
			clientAddr := msg.Conn.RemoteAddr().(*net.TCPAddr)
			bannedAt, banned := bannedMfs[clientAddr.IP.String()]

			if banned {
				t := BanLimit - time.Now().Sub(bannedAt).Seconds()
				if 0 < t && t < BanLimit {
					msg.Conn.Write([]byte(fmt.Sprintf("You are banned for %v seconds\n", t)))
					slog.Info(fmt.Sprintf("Client %v is banned", sensitive(clientAddr.String())))
					msg.Conn.Close()
				} else {
					delete(bannedMfs, clientAddr.IP.String())
				}
			}

			slog.Info(fmt.Sprintf("Client %v connected\n", sensitive(clientAddr.String())))
			clients[msg.Conn.RemoteAddr().String()] = &Client{
				Conn:        msg.Conn,
				LastMessage: time.Now(),
			}

		case ClientDisconnected:
			clientAddr := msg.Conn.RemoteAddr().(*net.TCPAddr)
			slog.Info(fmt.Sprintf("Client %v disconnected\n", sensitive(clientAddr.String())))
			delete(clients, clientAddr.String())

		case NewMessage:
			now := time.Now()
			clientAddr := msg.Conn.RemoteAddr().(*net.TCPAddr)
			client := clients[clientAddr.String()]

			// guard against pending messages from banned user
			if client == nil {
				msg.Conn.Close()
				continue
			}

			// ddos guard
			if now.Sub(client.LastMessage).Seconds() < MessageRate {
				client.StrikeCount += 1
				if client.StrikeCount >= StrikeLimit {
					bannedMfs[clientAddr.IP.String()] = now
					client.Conn.Close()
				}
				continue
			}

			// not utf8 string guard
			if !utf8.ValidString(msg.Text) {
				client.StrikeCount += 1
				if client.StrikeCount >= StrikeLimit {
					bannedMfs[clientAddr.IP.String()] = now
					client.Conn.Close()
				}
				continue
			}

			client.LastMessage = now
			slog.Info(fmt.Sprintf("Client %v sent message: %v\n", sensitive(clientAddr.String()), msg.Text))
			for _, v := range clients {
				if v.Conn.RemoteAddr().String() != clientAddr.String() {
					_, _ = v.Conn.Write([]byte(msg.Text))
				}
			}
		}
	}
}

func main() {
	buffer := make([]byte, BufSize)
	_, err := rand.Read(buffer)
	if err != nil {
		slog.Error(fmt.Sprintf("Could not generate a access token: %v", err))
		return
	}

	token := fmt.Sprintf("%02x", buffer)
	slog.Info(token)

	ln, err := net.Listen("tcp", ":"+Port)
	if err != nil {
		slog.Error(fmt.Sprintf("Could not start server on port %v\n%v\n", Port, sensitive(err.Error())))
		os.Exit(1)
	}

	slog.Info(fmt.Sprintf("Listening to TCP connections on port %v ...\n", Port))

	ch := make(chan Message)
	go server(ch)

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error(fmt.Sprintf("Could not accept the connection: %v\n", sensitive(err.Error())))
			continue
		}

		slog.Info(fmt.Sprintf("Accepted connection from %v\n", sensitive(conn.RemoteAddr().String())))

		go client(conn, ch, token)
	}
}
