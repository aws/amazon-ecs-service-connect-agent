package profiling

//func TestCompressFolder(t *testing.T) {
//	src := "example_folder"
//	dest := "example_folder.tar.gz"
//
//	err := CompressFolder(src, dest)
//	if err != nil {
//		t.Fatalf("Error compressing folder: %v", err)
//	}
//
//	tarfile, err := os.Open(dest)
//	if err != nil {
//		t.Fatalf("Error opening .tar.gz file: %v", err)
//	}
//	defer tarfile.Close()
//
//	gzipReader, err := gzip.NewReader(tarfile)
//	if err != nil {
//		t.Fatalf("Error opening .gzip reader: %v", err)
//	}
//	defer gzipReader.Close()
//
//	tarReader := tar.NewReader(gzipReader)
//
//	for {
//		header, err := tarReader.Next()
//		if err == io.EOF {
//			break
//		}
//		if err != nil {
//			t.Fatalf("Error reading tar archive: %v", err)
//		}
//
//		// Check that each file in the archive exists in the original folder
//		path := filepath.Join(src, header.Name)
//		_, err = os.Stat(path)
//		if err != nil {
//			t.Fatalf("File not found in original folder: %v", err)
//		}
//	}
//}
