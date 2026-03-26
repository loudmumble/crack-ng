# Create a mixed file
echo '5d41402abc4b2a76b9719d911017c592' > test_mixed.txt
echo '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy' >> test_mixed.txt
echo '8b1a9953c4611296a827abf8c47804d7' >> test_mixed.txt

# Run it headless to see if it correctly groups and routes
./target/release/crack-ng -H test_mixed.txt --no-tui
