package shared

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ToFileNotFound converts ENOENT to constants.ErrFileNotFound to make life simpler.
func ToFileNotFound(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, syscall.ENOENT) || os.IsNotExist(err) {
		return ErrFileNotFound
	}

	return err
}

func IsValidFileArg(logger LogI, name string, args []string) error {
	logger = Nop(logger)

	if len(args) != 1 {
		err := fmt.Errorf("%w: [%s] Expected 1 arg, got [%d]", ErrFileNotFound, name, len(args))
		logger.ErrorMsgf(err, "%s Failed to find valid file arg.", name)

		return err
	}

	filePath := args[0]
	if _, err := os.Stat(filePath); err != nil {
		err = ToFileNotFound(err)
		if errors.Is(err, ErrFileNotFound) {
			err = fmt.Errorf("%w: path [%s] was not found", err, filePath)
			logger.ErrorMsgf(err, "[%s] requires a target file, however [%s] did not exist.", name, filePath)

			return err
		}
	}

	return nil
}

func LoadFile(ctx context.Context, logger LogI, filePath string) ([]byte, error) {
	logger = Nop(logger)

	fileHandle, cleanPath, err := OpenFile(ctx, logger, filePath)
	if err != nil {
		err = fmt.Errorf("%w: failed to open path [%s]", err, filePath)
		logger.ErrorMsgf(err, "Open path [%s] failed.", cleanPath)

		return nil, err
	}

	defer fileHandle.Close()

	var data []byte

	data, err = io.ReadAll(fileHandle)
	if err != nil {
		err = fmt.Errorf("%w: failed to read path [%s]", err, cleanPath)
		logger.ErrorMsgf(err, "ReadAll [%s] failed.", cleanPath)

		return nil, err
	}

	return data, nil
}

func OpenFile(ctx context.Context, logger LogI, filePath string) (*os.File, string, error) {
	logger = Nop(logger)

	cleanPath, err := prepareOpen(ctx, logger, filePath)
	if err != nil {
		return nil, cleanPath, err
	}

	fileHandle, err := os.Open(cleanPath)
	if err != nil {
		err = fmt.Errorf("%w: failed to open path [%s]", err, cleanPath)
		logger.ErrorMsgf(err, "Open path [%s] failed.", cleanPath)

		return nil, cleanPath, err
	}

	return fileHandle, cleanPath, nil
}

func prepareOpen(ctx context.Context, logger LogI, filePath string) (string, error) {
	logger = Nop(logger)

	exists, cleanPath, err := FilePathExists(ctx, logger, filePath)
	if !exists || err != nil {
		if !exists {
			err = ErrFileNotFound
		}

		err = fmt.Errorf("%w: failed to clean path [%s]", err, filePath)
		logger.ErrorMsgf(err, "Validate path [%s] failed.", filePath)

		return cleanPath, err
	}

	if logger.IsDebugEnabled() {
		logger.DebugMsgf("LoadFile path [%s] is now [%s].", filePath, cleanPath)
	}

	return cleanPath, nil
}

func FilePathExists(ctx context.Context, logger LogI, filePath string) (bool, string, error) {
	logger = Nop(logger)

	cleanPath, err := ValidatePath(ctx, logger, filePath)
	if err != nil {
		err = fmt.Errorf("%w: failed to validate path [%s]", err, filePath)
		logger.ErrorMsg(err, "Failed to validate the path.")

		return false, cleanPath, err
	}

	_, err = os.Stat(cleanPath)

	if err == nil {
		// file exists
		return true, cleanPath, nil
	}

	if errors.Is(err, os.ErrNotExist) {
		// file does *not* exist, but cleanPath exists.
		return false, cleanPath, nil
	}

	err = fmt.Errorf("%w: the file path does not exist", err)
	logger.ErrorMsg(err, "Provided file path does not exist.")

	return false, cleanPath, err
}

func ValidatePath(ctx context.Context, logger LogI, path string) (string, error) {
	logger = Nop(logger)

	if path == "" {
		err := fmt.Errorf("%w: path was empty", ErrFileNotFound)
		logger.ErrorMsg(err, "The provided path was empty.")

		return "", err
	}

	cleanPath := filepath.Clean(path)
	if cleanPath == "." {
		err := fmt.Errorf("%w: path [%s] became [%s] after calling clean", ErrPathIsCurrentDirectory, path, cleanPath)
		logger.ErrorMsg(err, "Failed to clean the file path directory.")

		return cleanPath, err
	}

	if path == "/" {
		err := fmt.Errorf("%w: path is [/]", ErrPathIsRootDirectory)
		logger.ErrorMsg(err, "Failed to validate the path, the root is a directory.")

		return cleanPath, err
	}

	return cleanPath, nil
}
