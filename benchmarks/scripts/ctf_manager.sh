#!/bin/bash

# CTF Challenge Manager Script
# Usage: ./ctf_manager.sh <start|stop|test> <challenge_path>

set -e

SCRIPT_NAME=$(basename "$0")
NETWORK_NAME="ctfnet"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}[INFO]${NC} $message"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $SCRIPT_NAME <command> <challenge_path>"
    echo ""
    echo "Commands:"
    echo "  start    - Build and start the challenge container"
    echo "  stop     - Stop and remove the challenge container"
    echo "  test     - Test if the challenge server is accessible"
    echo "  status   - Show current container status"
    echo ""
    echo "Example:"
    echo "  $SCRIPT_NAME start /home/ubuntu/gym-env/ctf-archive/downunderctf2021/flagloader"
    echo "  $SCRIPT_NAME stop /home/ubuntu/gym-env/ctf-archive/downunderctf2021/flagloader"
    echo "  $SCRIPT_NAME test /home/ubuntu/gym-env/ctf-archive/downunderctf2021/flagloader"
}

# Function to validate challenge directory
validate_challenge_dir() {
    local challenge_path=$1
    
    if [ ! -d "$challenge_path" ]; then
        print_error "Challenge directory does not exist: $challenge_path"
        exit 1
    fi
    
    if [ ! -f "$challenge_path/docker-compose.yml" ] && [ ! -f "$challenge_path/Dockerfile" ]; then
        print_error "No docker-compose.yml or Dockerfile found in: $challenge_path"
        exit 1
    fi
    
    return 0
}

# Function to read challenge metadata
get_challenge_info() {
    local challenge_path=$1
    local challenge_json="$challenge_path/challenge.json"
    local compose_file="$challenge_path/docker-compose.yml"
    
    if [ -f "$challenge_json" ]; then
        CHALLENGE_NAME=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "$challenge_json" | cut -d'"' -f4)
        INTERNAL_PORT=$(grep -o '"internal_port"[[:space:]]*:[[:space:]]*[0-9]*' "$challenge_json" | grep -o '[0-9]*$')
        CHALLENGE_NAME=${CHALLENGE_NAME:-$(basename "$challenge_path")}
        INTERNAL_PORT=${INTERNAL_PORT:-1337}
    else
        CHALLENGE_NAME=$(basename "$challenge_path")
        INTERNAL_PORT=1337
        print_warning "No challenge.json found, using defaults: name=$CHALLENGE_NAME, port=$INTERNAL_PORT"
    fi
    
    # Extract domain alias from docker-compose.yml
    if [ -f "$compose_file" ]; then
        DOMAIN_ALIAS=$(grep -A 10 "aliases:" "$compose_file" | grep -o "- .*" | sed 's/^- *//' | head -1)
        if [ -n "$DOMAIN_ALIAS" ]; then
            print_status $BLUE "Found domain alias: $DOMAIN_ALIAS"
        fi
    fi
}

# Function to setup domain alias in /etc/hosts
setup_domain_alias() {
    if [ -n "$DOMAIN_ALIAS" ]; then
        if ! grep -q "$DOMAIN_ALIAS" /etc/hosts 2>/dev/null; then
            print_status $YELLOW "Domain alias $DOMAIN_ALIAS not found in /etc/hosts"
            echo -e "${BLUE}Would you like to add '127.0.0.1 $DOMAIN_ALIAS' to /etc/hosts? (y/n):${NC}"
            read -r response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                if echo "127.0.0.1 $DOMAIN_ALIAS" | sudo tee -a /etc/hosts > /dev/null; then
                    print_success "Added $DOMAIN_ALIAS to /etc/hosts"
                    print_status $GREEN "You can now access the service via: nc $DOMAIN_ALIAS $INTERNAL_PORT"
                else
                    print_warning "Failed to add to /etc/hosts (needs sudo privileges)"
                fi
            fi
        else
            print_status $GREEN "Domain alias $DOMAIN_ALIAS already configured in /etc/hosts"
        fi
    fi
}

# Function to remove domain alias from /etc/hosts
remove_domain_alias() {
    if [ -n "$DOMAIN_ALIAS" ]; then
        if grep -q "$DOMAIN_ALIAS" /etc/hosts 2>/dev/null; then
            print_status $YELLOW "Removing $DOMAIN_ALIAS from /etc/hosts"
            sudo sed -i "/$DOMAIN_ALIAS/d" /etc/hosts 2>/dev/null || print_warning "Failed to remove from /etc/hosts"
        fi
    fi
}

# Function to ensure ctfnet network exists
ensure_network() {
    if ! docker network ls | grep -q "$NETWORK_NAME"; then
        print_status $BLUE "Creating Docker network: $NETWORK_NAME"
        docker network create "$NETWORK_NAME"
    else
        print_status $BLUE "Docker network $NETWORK_NAME already exists"
    fi
}

# Check if required tools are installed
check_dependencies() {
    local missing_deps=()
    
    # Check for docker
    if ! command -v "docker" &> /dev/null; then
        missing_deps+=("docker")
    fi
    
    # Check for docker compose (v2 plugin) or docker-compose (v1 standalone)
    if ! docker compose version &> /dev/null && ! command -v "docker-compose" &> /dev/null; then
        missing_deps+=("docker-compose or docker compose plugin")
    fi
    
    # Check for nc (netcat)
    if ! command -v "nc" &> /dev/null; then
        missing_deps+=("nc")
    fi
    
    # Check for ss or netstat
    if ! command -v "ss" &> /dev/null && ! command -v "netstat" &> /dev/null; then
        missing_deps+=("ss or netstat")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        print_status $YELLOW "Please install the missing dependencies and try again"
        exit 1
    fi
    
    # Set the compose command to use
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi
    
    # Set the network stat command to use
    if command -v "ss" &> /dev/null; then
        NETSTAT_CMD="ss"
    else
        NETSTAT_CMD="netstat"
    fi
}

# Function to start the challenge
start_challenge() {
    local challenge_path=$1
    
    print_status $BLUE "Starting challenge: $CHALLENGE_NAME"
    print_status $BLUE "Challenge path: $challenge_path"
    print_status $BLUE "Internal port: $INTERNAL_PORT"
    
    cd "$challenge_path"
    
    # Ensure network exists
    ensure_network
    
    # Stop existing container if running
    if $COMPOSE_CMD ps | grep -q "Up"; then
        print_warning "Container already running, stopping first..."
        $COMPOSE_CMD down
    fi
    
    # Build and start the container
    print_status $BLUE "Building and starting container..."
    $COMPOSE_CMD up --build -d
    
    # Wait a moment for the service to start
    sleep 3
    
    # Check if container is running
    if $COMPOSE_CMD ps | grep -q "Up"; then
        print_success "Challenge started successfully!"
        print_status $GREEN "Container is running on port $INTERNAL_PORT"
        print_status $YELLOW "You can test connectivity with: $SCRIPT_NAME test $challenge_path"
        
        # Setup domain alias if configured
        setup_domain_alias
        
        echo ""
        print_status $GREEN "Access methods:"
        print_status $WHITE "  • localhost: nc localhost $INTERNAL_PORT"
        if [ -n "$DOMAIN_ALIAS" ]; then
            print_status $WHITE "  • domain alias: nc $DOMAIN_ALIAS $INTERNAL_PORT"
        fi
    else
        print_error "Failed to start container"
        $COMPOSE_CMD logs
        exit 1
    fi
}

# Function to stop the challenge
stop_challenge() {
    local challenge_path=$1
    
    print_status $BLUE "Stopping challenge: $CHALLENGE_NAME"
    print_status $BLUE "Challenge path: $challenge_path"
    
    cd "$challenge_path"
    
    # Stop and remove containers
    $COMPOSE_CMD down
    
    # Remove images if they exist
    if docker images | grep -q "$(basename $challenge_path)"; then
        print_status $BLUE "Removing challenge images..."
        $COMPOSE_CMD down --rmi all
    fi
    
    # Clean up domain alias
    if [ -n "$DOMAIN_ALIAS" ]; then
        echo -e "${BLUE}Remove $DOMAIN_ALIAS from /etc/hosts? (y/n):${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            remove_domain_alias
        fi
    fi
    
    print_success "Challenge stopped and cleaned up successfully!"
}

# Function to test the challenge
test_challenge() {
    local challenge_path=$1
    
    print_status $BLUE "Testing challenge: $CHALLENGE_NAME"
    print_status $BLUE "Attempting to connect to localhost:$INTERNAL_PORT"
    
    cd "$challenge_path"
    
    # Check if container is running
    if ! $COMPOSE_CMD ps | grep -q "Up"; then
        print_error "Container is not running. Start it first with: $SCRIPT_NAME start $challenge_path"
        exit 1
    fi
    
    # Test connection using netcat with timeout
    if timeout 5 nc -z localhost "$INTERNAL_PORT" 2>/dev/null; then
        print_success "Connection successful! Server is listening on port $INTERNAL_PORT"
        
        # Try to get a response from the service
        print_status $BLUE "Attempting to interact with the service..."
        echo "Testing connection..." | timeout 5 nc localhost "$INTERNAL_PORT" || true
        
    else
        print_error "Connection failed! Server is not responding on port $INTERNAL_PORT"
        print_status $YELLOW "Container logs:"
        $COMPOSE_CMD logs --tail=20
        exit 1
    fi
}

# Function to show container status
show_status() {
    local challenge_path=$1
    
    print_status $BLUE "Status for challenge: $CHALLENGE_NAME"
    print_status $BLUE "Challenge path: $challenge_path"
    
    cd "$challenge_path"
    
    echo ""
    print_status $BLUE "Container status:"
    $COMPOSE_CMD ps
    
    echo ""
    print_status $BLUE "Port status:"
    if [ "$NETSTAT_CMD" = "ss" ]; then
        if ss -ln | grep -q ":$INTERNAL_PORT "; then
            print_success "Port $INTERNAL_PORT is listening"
        else
            print_warning "Port $INTERNAL_PORT is not listening"
        fi
    else
        if netstat -ln 2>/dev/null | grep -q ":$INTERNAL_PORT "; then
            print_success "Port $INTERNAL_PORT is listening"
        else
            print_warning "Port $INTERNAL_PORT is not listening"
        fi
    fi
}

# Main script logic
main() {
    if [ $# -lt 2 ]; then
        show_usage
        exit 1
    fi
    
    local command=$1
    local challenge_path=$2
    
    # Validate inputs
    validate_challenge_dir "$challenge_path"
    get_challenge_info "$challenge_path"
    
    # Execute command
    case $command in
        start)
            start_challenge "$challenge_path"
            ;;
        stop)
            stop_challenge "$challenge_path"
            ;;
        test)
            test_challenge "$challenge_path"
            ;;
        status)
            show_status "$challenge_path"
            ;;
        *)
            print_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run dependency check and main function
check_dependencies
main "$@" 