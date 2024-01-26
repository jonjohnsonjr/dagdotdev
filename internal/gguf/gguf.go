package gguf

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// GGUFFileReader represents a reader for GGUF files
type GGUFFileReader struct {
	reader io.Reader
}

// NewGGUFFileReader creates a new GGUFFileReader with the given io.Reader
func NewGGUFFileReader(reader io.Reader) *GGUFFileReader {
	return &GGUFFileReader{reader: reader}
}

// ReadGGUFHeader reads the GGUF header from the reader
func (r *GGUFFileReader) ReadGGUFHeader() (*GGUFHeader, error) {
	header := &GGUFHeader{}
	if err := binary.Read(r.reader, binary.LittleEndian, header); err != nil {
		return nil, err
	}

	return header, nil
}

func (r *GGUFFileReader) ReadMetadataKVs(count uint64) ([]GGUFMetadataKV, error) {
	kvs := make([]GGUFMetadataKV, count)
	for i := range kvs {
		kv := &kvs[i]
		key, err := r.readString()
		if err != nil {
			return nil, err
		}
		kv.Key = key
		if err := binary.Read(r.reader, binary.LittleEndian, &kv.ValueType); err != nil {
			return nil, err
		}

		v, err := r.ReadValue(kv.ValueType)
		if err != nil {
			return nil, err
		}
		kv.Value = v
	}

	return kvs, nil
}

// GGUFString represents the GGUF string in Go
type GGUFString struct {
	Len    uint64
	String string
}

func (r *GGUFFileReader) readString() (string, error) {
	len := uint64(0)
	if err := binary.Read(r.reader, binary.LittleEndian, &len); err != nil {
		return "", err
	}
	buf := make([]byte, int(len))
	if err := binary.Read(r.reader, binary.LittleEndian, &buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// ReadGGUFTensorInfos reads the GGUF tensor infos from the reader
func (r *GGUFFileReader) ReadGGUFTensorInfos(count uint64) ([]GGUFTensorInfo, error) {
	tensorInfos := make([]GGUFTensorInfo, count)

	for i := range tensorInfos {
		ti := &tensorInfos[i]
		name, err := r.readString()
		if err != nil {
			return nil, err
		}
		ti.Name = name

		if err := binary.Read(r.reader, binary.LittleEndian, &ti.NDimensions); err != nil {
			return nil, err
		}
		ti.Dimensions = make([]uint64, ti.NDimensions)
		if err := binary.Read(r.reader, binary.LittleEndian, &ti.Dimensions); err != nil {
			return nil, err
		}
		if err := binary.Read(r.reader, binary.LittleEndian, &ti.Type); err != nil {
			return nil, err
		}
		if err := binary.Read(r.reader, binary.LittleEndian, &ti.Offset); err != nil {
			return nil, err
		}
	}

	return tensorInfos, nil
}

// ReadGGUFFile reads the entire GGUF file from the reader
func (r *GGUFFileReader) ReadGGUFFile() (*GGUFFile, error) {
	header, err := r.ReadGGUFHeader()
	if err != nil {
		return nil, err
	}

	kvs, err := r.ReadMetadataKVs(header.MetadataKVCount)
	if err != nil {
		return nil, err
	}

	// // Read tensor infos
	// tensorInfos, err := r.ReadGGUFTensorInfos(header.TensorCount)
	// if err != nil {
	// 	return nil, err
	// }

	// // Read padding
	// paddingSize := alignOffset(GGUFHeaderSize + uint64(len(tensorInfos)*int(unsafe.Sizeof(GGUFTensorInfo{}))))
	// padding := make([]byte, paddingSize)
	// _, err = io.ReadFull(r.reader, padding)
	// if err != nil {
	// 	return nil, err
	// }

	// // Read tensor data
	// tensorData := make([]byte, alignOffset(paddingSize))
	// _, err = io.ReadFull(r.reader, tensorData)
	// if err != nil {
	// 	return nil, err
	// }

	// return &GGUFFile{
	// 	Header:      *header,
	// 	MetadataKV:  kvs,
	// 	TensorInfos: tensorInfos,
	// 	Padding:     padding,
	// 	TensorData:  tensorData,
	// }, nil
	return &GGUFFile{
		Header:     *header,
		MetadataKV: kvs,
	}, nil
}

func main() {
	ggufReader := NewGGUFFileReader(os.Stdin)
	ggufFile, err := ggufReader.ReadGGUFFile()
	if err != nil {
		fmt.Println("Error reading GGUF file:", err)
		return
	}

	// Use ggufFile as needed
	fmt.Printf("GGUF Header: %+v\n", ggufFile.Header)
	// fmt.Printf("Tensor Infos: %+v\n", ggufFile.TensorInfos)
}

// ggmlType represents the GGML type enum in Go
type ggmlType uint32

const (
	GGMLTypeF32 ggmlType = iota
	GGMLTypeF16
	GGMLTypeQ40
	GGMLTypeQ41
	GGMLTypeQ50 = 6
	GGMLTypeQ51
	GGMLTypeQ80
	GGMLTypeQ81
	GGMLTypeQ2K
	GGMLTypeQ3K
	GGMLTypeQ4K
	GGMLTypeQ5K
	GGMLTypeQ6K
	GGMLTypeQ8K
	GGMLTypeI8
	GGMLTypeI16
	GGMLTypeI32
	GGMLTypeCount
)

// ggufMetadataValueType represents the GGUF metadata value type enum in Go
type ggufMetadataValueType uint32

const (
	GGUFMetadataValueTypeUint8 ggufMetadataValueType = iota
	GGUFMetadataValueTypeInt8
	GGUFMetadataValueTypeUint16
	GGUFMetadataValueTypeInt16
	GGUFMetadataValueTypeUint32
	GGUFMetadataValueTypeInt32
	GGUFMetadataValueTypeFloat32
	GGUFMetadataValueTypeBool
	GGUFMetadataValueTypeString
	GGUFMetadataValueTypeArray
	GGUFMetadataValueTypeUint64
	GGUFMetadataValueTypeInt64
	GGUFMetadataValueTypeFloat64
)

func (r *GGUFFileReader) ReadValue(typ ggufMetadataValueType) (string, error) {
	switch typ {
	case GGUFMetadataValueTypeUint8:
		val := uint8(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%d", val), nil
	case GGUFMetadataValueTypeInt8:
		val := int8(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%d", val), nil
	case GGUFMetadataValueTypeUint16:
		val := uint16(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%d", val), nil
	case GGUFMetadataValueTypeInt16:
		val := int16(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%d", val), nil
	case GGUFMetadataValueTypeUint32:
		val := uint32(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%d", val), nil
	case GGUFMetadataValueTypeInt32:
		val := int32(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%d", val), nil
	case GGUFMetadataValueTypeFloat32:
		val := float32(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%f", val), nil
	case GGUFMetadataValueTypeBool:
		val := false
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%t", val), nil
	case GGUFMetadataValueTypeString:
		return r.readString()
	case GGUFMetadataValueTypeArray:
		atyp := ggufMetadataValueType(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &atyp); err != nil {
			return "", err
		}
		if atyp == GGUFMetadataValueTypeArray {
			return "", fmt.Errorf("this is an array of arrays and I don't want to render that")
		}
		alen := uint64(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &alen); err != nil {
			return "", err
		}

		limit := alen
		if limit > 16 {
			limit = 16
		}
		avs := make([]string, 0, int(limit))
		for i := uint64(0); i < alen; i++ {
			av, err := r.ReadValue(atyp)
			if err != nil {
				return "", err
			}
			if i < limit {
				avs = append(avs, av)
			} else if i == limit {
				avs = append(avs, fmt.Sprintf("... (%d total elements)", alen))
			}
		}

		return fmt.Sprintf("%v", avs), nil
	case GGUFMetadataValueTypeUint64:
		val := uint64(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%d", val), nil
	case GGUFMetadataValueTypeInt64:
		val := int64(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%d", val), nil
	case GGUFMetadataValueTypeFloat64:
		val := float64(0)
		if err := binary.Read(r.reader, binary.LittleEndian, &val); err != nil {
			return "", err
		}

		return fmt.Sprintf("%f", val), nil
	}

	return "", fmt.Errorf("unexpected type: %d", typ)
}

// GGUFMetadataKV represents the GGUF metadata key-value pair in Go
type GGUFMetadataKV struct {
	Key       string
	ValueType ggufMetadataValueType
	Value     string
}

// GGUFHeader represents the GGUF header in Go
type GGUFHeader struct {
	Magic           uint32
	Version         uint32
	TensorCount     uint64
	MetadataKVCount uint64
}

// alignOffset calculates the aligned offset in Go
func alignOffset(offset uint64) uint64 {
	const alignment = 8 // Assuming ALIGNMENT is 8 in the original code
	return offset + (alignment-(offset%alignment))%alignment
}

// GGUFTensorInfo represents the GGUF tensor info in Go
type GGUFTensorInfo struct {
	Name        string
	NDimensions uint32
	Dimensions  []uint64
	Type        ggmlType
	Offset      uint64
}

// GGUFFile represents the GGUF file in Go
type GGUFFile struct {
	Header      GGUFHeader
	MetadataKV  []GGUFMetadataKV
	TensorInfos []GGUFTensorInfo
	Padding     []byte
	TensorData  []byte
}
