package main

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Port        = "9090"
	SafeMode    = true
	MessageRate = 1.0
	StrikeLimit = 3
	BanLimit    = 5 * 60 // minutes
	BufSize     = 16
)

func censure(msg string) string {
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
	authed      bool
}

func client(conn net.Conn, ch chan Message) {
	clientAddr := conn.RemoteAddr()
	if clientAddr == nil {
		slog.Error("Could not get address from sender\n")
		conn.Close()
		return
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

func server(ch chan Message, token string) {
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
					slog.Info(fmt.Sprintf("Client %v is banned", censure(clientAddr.String())))
					msg.Conn.Close()
				} else {
					delete(bannedMfs, clientAddr.IP.String())
				}
			}

			slog.Info(fmt.Sprintf("Client %v connected\n", censure(clientAddr.String())))
			clients[msg.Conn.RemoteAddr().String()] = &Client{
				Conn:        msg.Conn,
				LastMessage: time.Now(),
				authed:      false,
			}

			_, err := msg.Conn.Write([]byte("Token: "))
			if err != nil {
				slog.Info(
					fmt.Sprintf("Could not send Token prompt to %v: %v\n",
						censure(clientAddr.String()),
						censure(err.Error())))
				msg.Conn.Close()
			}

		case ClientDisconnected:
			clientAddr := msg.Conn.RemoteAddr().(*net.TCPAddr)
			slog.Info(fmt.Sprintf("Client %v disconnected\n", censure(clientAddr.String())))
			delete(clients, clientAddr.String())

		case NewMessage:
			now := time.Now()
			clientAddr := msg.Conn.RemoteAddr().(*net.TCPAddr)
			client := clients[clientAddr.String()]

			// guard against pending messages from banned user
			if client == nil {
				msg.Conn.Close()
			}

			// ddos guard
			if now.Sub(client.LastMessage).Seconds() < MessageRate {
				client.StrikeCount += 1
				if client.StrikeCount >= StrikeLimit {
					slog.Info(fmt.Sprintf("Client %v got banned", censure(clientAddr.String())))
					_, err := client.Conn.Write([]byte("You are banned\n"))
					if err != nil {
						slog.Info(
							fmt.Sprintf("Could not send Token prompt to %v: %v\n",
								censure(clientAddr.String()),
								censure(err.Error())))
					}
					client.Conn.Close()
					bannedMfs[clientAddr.IP.String()] = now
					delete(clients, clientAddr.String())
				}
				continue
			}

			// not utf8 string guard
			if !utf8.ValidString(msg.Text) {
				client.StrikeCount += 1
				if client.StrikeCount >= StrikeLimit {
					bannedMfs[clientAddr.IP.String()] = now
					msg.Conn.Close()
				}
			}

			// auth guard
			if !client.authed {
				if token != strings.TrimSpace(msg.Text) {
					slog.Info(fmt.Sprintf("%v Failed authorization", censure(clientAddr.String())))
					_, err := msg.Conn.Write([]byte("Invalid authorization token\n"))
					if err != nil {
						slog.Info(
							fmt.Sprintf("Could not notify client %v about invalid token: %v\n",
								censure(clientAddr.String()),
								censure(err.Error())))
					}
					delete(clients, clientAddr.String())
					msg.Conn.Close()
				}
				_, err := msg.Conn.Write([]byte("Welcome to Chatti!\n"))
				if err != nil {
					slog.Info(
						fmt.Sprintf("Could not greet %v: %v\n",
							censure(clientAddr.String()),
							censure(err.Error())))
				}
				slog.Info(fmt.Sprintf("Client %v is authorized\n", clientAddr))
				client.authed = true
			}

			client.LastMessage = now
			slog.Info(
				fmt.Sprintf("Client %v sent message: %v",
					censure(clientAddr.String()),
					msg.Text))

			for _, v := range clients {
				if v.authed && v.Conn.RemoteAddr().String() != clientAddr.String() {
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
		slog.Error(fmt.Sprintf("Could not start server on port %v\n%v\n", Port, censure(err.Error())))
		os.Exit(1)
	}
	defer ln.Close()

	slog.Info(fmt.Sprintf("Listening to TCP connections on port %v ...\n", Port))

	ch := make(chan Message)
	go server(ch, token)
	defer close(ch)

	for {
		conn, err := ln.Accept()
		if err != nil {
			slog.Error(fmt.Sprintf("Could not accept the connection: %v\n", censure(err.Error())))
			continue
		}

		slog.Info(fmt.Sprintf("Accepted connection from %v\n", censure(conn.RemoteAddr().String())))

		go client(conn, ch)
	}
}
