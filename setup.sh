#!/bin/bash

SCRIPT_DIR=$(pwd)

# Create NetScan with the script content
cat <<EOF > NetScan
#!/bin/bash

# Hardcode the directory to the script's original location
cd "$SCRIPT_DIR"

# Activate the virtual environment
source ve/bin/activate

# Function to kill server running on port 25250
cleanup() {
    echo "Cleaning up..."
    lsof -ti:25250 | xargs kill
}

# Trap EXIT signal to call cleanup function
trap cleanup EXIT

#Kill port 25250 if in use
lsof -ti:25250 | xargs kill

# Run NetScan in the background and get its PID
python3 main.py &
NETSCAN_PID=$!

# Wait for the server to start
sleep 2

# Open in Google Chrome
open -a "Google Chrome" http://127.0.0.1:25250

# Wait for NetScan process to finish
wait $NETSCAN_PID
EOF

# Move NetScan to ~/bin and make it executable
mv NetScan /opt/homebrew/bin/
chmod +x /opt/homebrew/bin/NetScan

source ve/bin/activate

pip3 install -r requirements.txt

brew install nmap

NetScan