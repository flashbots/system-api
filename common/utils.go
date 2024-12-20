package common

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
)

// GetEnvInt returns the value of the environment variable named by key, or defaultValue if the environment variable
// doesn't exist or is not a valid integer
func GetEnvInt(key string, defaultValue int) int {
	if value, ok := os.LookupEnv(key); ok {
		val, err := strconv.Atoi(value)
		if err == nil {
			return val
		}
	}
	return defaultValue
}

// GetEnv returns the value of the environment variable named by key, or defaultValue if the environment variable doesn't exist
func GetEnv(key, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func Shellout(command string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(ShellToUse, "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}
