package util

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func ReadLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		targets = append(targets, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

func StreamLinesFromFile(filename string, lineChannel chan<- string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	defer close(lineChannel) // Close the channel when the function returns

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineChannel <- scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

// GenerateIPsFromCIDR takes a CIDR range and sends each IP address on the provided channel.
func GenerateIPsFromCIDR(cidr string, ipChannel chan<- string) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		// Don't include the network and broadcast addresses
		if !ip.Equal(ipnet.IP) && !ip.Equal(broadcastAddress(ipnet)) {
			ipChannel <- ip.String()
		}
	}
	close(ipChannel)
	return nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func broadcastAddress(network *net.IPNet) net.IP {
	ip := network.IP.To4()
	mask := network.Mask
	broadcast := net.IPv4(0, 0, 0, 0).To4()
	for i := range ip {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

func LogHash(ipAddress, username, salt, hash, outputPath string) error {
	// Open the file in append mode, or create it if it doesn't exist
	file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("Failed to open or create output file: %v", err)
	}
	defer file.Close()

	// Create the log line
	logLine := fmt.Sprintf("%s %s:%s:%s\n", ipAddress, username, salt, hash)

	// Append the log line to the file
	_, err = file.WriteString(logLine)
	if err != nil {
		return fmt.Errorf("Failed to write to output file: %v", err)
	}

	return nil
}
