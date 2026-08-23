package upgrader

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func ExtractBinary(archivePath, binaryName, destination string, maxBytes int64) error {
	if maxBytes <= 0 {
		return errors.New("extraction size limit must be positive")
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	var data []byte
	switch {
	case magic[0] == 0x1f && magic[1] == 0x8b:
		data, err = extractTarGz(f, binaryName, maxBytes)
	case string(magic[:2]) == "PK":
		f.Close()
		data, err = extractZip(archivePath, binaryName, maxBytes)
	default:
		err = errors.New("artifact must be tar.gz or zip")
	}
	if err != nil {
		return err
	}
	if data == nil {
		return fmt.Errorf("archive does not contain %s", binaryName)
	}
	return writeExecutable(destination, data)
}

func extractTarGz(r io.Reader, binaryName string, maxBytes int64) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var found []byte
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if err := safeArchivePath(h.Name); err != nil {
			return nil, err
		}
		if h.Size < 0 || h.Size > maxBytes-total {
			return nil, errors.New("archive expands beyond size limit")
		}
		total += h.Size
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return nil, fmt.Errorf("archive contains unsupported entry %q", h.Name)
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == binaryName {
			if found != nil {
				return nil, fmt.Errorf("archive contains duplicate %s", binaryName)
			}
			found, err = readLimited(tr, maxBytes)
			if err != nil {
				return nil, err
			}
		}
	}
	return found, nil
}

func extractZip(archivePath, binaryName string, maxBytes int64) ([]byte, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var found []byte
	var total uint64
	for _, entry := range zr.File {
		if err := safeArchivePath(entry.Name); err != nil {
			return nil, err
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("archive contains symlink %q", entry.Name)
		}
		if entry.UncompressedSize64 > uint64(maxBytes)-total {
			return nil, errors.New("archive expands beyond size limit")
		}
		total += entry.UncompressedSize64
		if entry.FileInfo().IsDir() || path.Base(entry.Name) != binaryName {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("archive contains duplicate %s", binaryName)
		}
		r, err := entry.Open()
		if err != nil {
			return nil, err
		}
		found, err = readLimited(r, maxBytes)
		r.Close()
		if err != nil {
			return nil, err
		}
	}
	return found, nil
}

func safeArchivePath(name string) error {
	normalized := strings.ReplaceAll(name, "\\", "/")
	for _, part := range strings.Split(normalized, "/") {
		if part == ".." {
			return fmt.Errorf("unsafe archive path %q", name)
		}
	}
	clean := path.Clean(normalized)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || path.IsAbs(clean) || filepath.IsAbs(name) {
		return fmt.Errorf("unsafe archive path %q", name)
	}
	return nil
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("extracted binary exceeds size limit")
	}
	return b, nil
}

func writeExecutable(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
