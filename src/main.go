package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"
	"unicode/utf8"
)

const (
	Port        = "9090"
	SafeMode    = true
	MessageRate = 1.0
	StrikeLimit = 3
	BanLimit    = 5 * 60 // minutes
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

func client(conn net.Conn, ch chan Message) {
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

		go client(conn, ch)
	}
}
