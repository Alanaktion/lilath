package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/alanaktion/lilath/internal/auth"
	"golang.org/x/term"
)

func main() {
	credsFile := flag.String("f", "users.txt", "path to credentials file")
	deleteUser := flag.String("delete", "", "username to delete")
	listUsers := flag.Bool("list", false, "list all usernames")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `lilath-adduser — manage lilath credentials

Usage:
  adduser [flags] [username]

Flags:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  adduser alice                    # add or update user 'alice'
  adduser -f /etc/lilath/users.txt alice
  adduser -delete alice            # remove user 'alice'
  adduser -list                    # list all users
`)
	}
	flag.Parse()

	// Load existing credentials (or start fresh).
	creds, err := auth.LoadCredentials(*credsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading credentials: %v\n", err)
		os.Exit(1)
	}
	entries := creds.ReadAll()

	switch {
	case *listUsers:
		if len(entries) == 0 {
			fmt.Println("(no users)")
			return
		}
		for u := range entries {
			fmt.Println(u)
		}

	case *deleteUser != "":
		if _, ok := entries[*deleteUser]; !ok {
			fmt.Fprintf(os.Stderr, "user %q not found\n", *deleteUser)
			os.Exit(1)
		}
		delete(entries, *deleteUser)
		if err := auth.WriteCredentials(*credsFile, entries); err != nil {
			fmt.Fprintf(os.Stderr, "error writing credentials: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("user %q deleted\n", *deleteUser)

	default:
		username := flag.Arg(0)
		if username == "" {
			fmt.Fprint(os.Stderr, "username: ")
			username = readLine()
		}
		if strings.TrimSpace(username) == "" {
			fmt.Fprintln(os.Stderr, "username cannot be empty")
			os.Exit(1)
		}

		fmt.Fprint(os.Stderr, "password: ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
			os.Exit(1)
		}
		if len(password) == 0 {
			fmt.Fprintln(os.Stderr, "password cannot be empty")
			os.Exit(1)
		}

		fmt.Fprint(os.Stderr, "confirm password: ")
		confirm, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading password: %v\n", err)
			os.Exit(1)
		}
		if string(password) != string(confirm) {
			fmt.Fprintln(os.Stderr, "passwords do not match")
			os.Exit(1)
		}

		hash, err := auth.HashPassword(string(password))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error hashing password: %v\n", err)
			os.Exit(1)
		}

		_, exists := entries[username]
		entries[username] = hash
		if err := auth.WriteCredentials(*credsFile, entries); err != nil {
			fmt.Fprintf(os.Stderr, "error writing credentials: %v\n", err)
			os.Exit(1)
		}

		if exists {
			fmt.Printf("user %q updated\n", username)
		} else {
			fmt.Printf("user %q added\n", username)
		}
	}
}

func readLine() string {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}
