echo '5d41402abc4b2a76b9719d911017c592' > test_mixed.txt
echo '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy' >> test_mixed.txt
./target/release/crack-ng --no-tui -H test_mixed.txt
