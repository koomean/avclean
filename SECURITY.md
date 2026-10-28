# Security

Please use GitHub's private vulnerability reporting for security issues. Avoid
publishing scanned filenames, personal documents, credentials or live malware in
public issues. Reproduce issues with a harmless generated file when possible.

avclean is an on-demand frontend to ClamAV. It does not provide real-time endpoint
protection. Signatures and the engine require updates, and no detection engine can
guarantee that a file is harmless. Review detections before moving files.

The offline self-test uses an ordinary generated text file and a custom matching
signature. It never downloads or executes malware.
