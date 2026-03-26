echo '5d41402abc4b2a76b9719d911017c592' > test_md5.txt
echo '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy' > test_bcrypt.txt
echo '$pbkdf2-sha256$1000$lZ02zP/1Xl0$P6H/fC' > test_pbkdf2.txt

./target/release/crack-ng -H test_md5.txt
echo "---"
./target/release/crack-ng -H test_bcrypt.txt
echo "---"
./target/release/crack-ng -H test_pbkdf2.txt
