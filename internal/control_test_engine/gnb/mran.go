package gnb

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	logger "github.com/Alonza0314/logger-go"
)

func mRanActionUsage() {
	logger.Info("MRAN", "************************************")
	logger.Info("MRAN", "* Usage: ping <dest_ip> -c <times> *")
	logger.Info("MRAN", "*        exit                      *")
	logger.Info("MRAN", "************************************")
}

func MranAction() {
	reader := bufio.NewReader(os.Stdin)
	mRanActionUsage()
	for {
		fmt.Print("MRAN> ")
		input, _ := reader.ReadString('\n')
		if input == "\n" {
			continue
		}
		input = strings.TrimSpace(input)
		parts := strings.Split(input, " ")
		switch parts[0] {
		case "ping":
			if len(parts) != 4 || parts[2] != "-c" {
				logger.Error("MRAN", "Invalid input format. Usage: ping <dest_ip> -c <times>")
				continue
			}
			cmd := exec.Command("ping", "-I", "val0000000001", parts[1], parts[2], parts[3])

			stdout, err := cmd.StdoutPipe()
			if err != nil {
				logger.Error("MRAN", fmt.Sprintf("Failed to create stdout pipe: %v", err))
				continue
			}

			if err := cmd.Start(); err != nil {
				logger.Error("MRAN", fmt.Sprintf("Failed to start ping: %v", err))
				continue
			}

			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				fmt.Println(scanner.Text())
			}

			if err := cmd.Wait(); err != nil {
				logger.Error("MRAN", fmt.Sprintf("Ping command failed: %v", err))
				continue
			}
		case "exit":
			return
		default:
			logger.Error("MRAN", "Invalid input")
			mRanActionUsage()
		}
	}
}
