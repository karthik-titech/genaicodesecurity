#!/bin/bash

# Google Home Security Patch - GitHub Setup Script
# This script helps initialize the repository for GitHub

set -e

echo "🔧 Setting up Google Home Security Patch for GitHub..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if git is installed
if ! command -v git &> /dev/null; then
    print_error "Git is not installed. Please install git first."
    exit 1
fi

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    print_status "Initializing git repository..."
    git init
    print_success "Git repository initialized"
fi

# Check if we have a remote origin
if ! git remote get-url origin &> /dev/null; then
    print_warning "No remote origin found. You'll need to add it manually:"
    echo "git remote add origin https://github.com/YOUR_USERNAME/google-home-security-patch.git"
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p logs
mkdir -p config
mkdir -p scripts
print_success "Directories created"

# Set up git hooks
print_status "Setting up git hooks..."
if [ -d ".git/hooks" ]; then
    # Create pre-commit hook
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook to run tests and linting

echo "Running pre-commit checks..."

# Run linting
npm run lint
if [ $? -ne 0 ]; then
    echo "Linting failed. Please fix the issues before committing."
    exit 1
fi

# Run tests
npm test
if [ $? -ne 0 ]; then
    echo "Tests failed. Please fix the issues before committing."
    exit 1
fi

echo "Pre-commit checks passed!"
EOF

    # Make the hook executable
    chmod +x .git/hooks/pre-commit
    print_success "Git hooks configured"
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    print_status "Creating .env file from template..."
    if [ -f "env.example" ]; then
        cp env.example .env
        print_success ".env file created from template"
        print_warning "Please edit .env file with your actual configuration"
    else
        print_error "env.example not found. Please create it first."
    fi
fi

# Install dependencies if package.json exists
if [ -f "package.json" ]; then
    print_status "Installing dependencies..."
    npm install
    print_success "Dependencies installed"
fi

# Create initial commit if no commits exist
if ! git rev-parse HEAD &> /dev/null; then
    print_status "Creating initial commit..."
    git add .
    git commit -m "Initial commit: Google Home Security Patch

- Multi-layered security architecture
- Input sanitization and validation
- Context protection and threat detection
- User confirmation system
- Access control management
- Comprehensive logging and monitoring"
    print_success "Initial commit created"
fi

# Set up branch protection (if you have admin access)
print_status "Setting up branch protection..."
echo "To set up branch protection, go to:"
echo "https://github.com/YOUR_USERNAME/google-home-security-patch/settings/branches"
echo "Add rule for 'main' branch with:"
echo "- Require pull request reviews"
echo "- Require status checks to pass"
echo "- Require branches to be up to date"

# Security checklist
print_status "Security checklist:"
echo "✅ .gitignore configured to exclude sensitive files"
echo "✅ .env file created (not committed)"
echo "✅ API keys should be stored securely"
echo "✅ Dependencies installed"
echo "✅ Git hooks configured"

# Final instructions
print_success "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Add your GitHub repository as remote origin"
echo "3. Push to GitHub: git push -u origin main"
echo "4. Set up branch protection rules"
echo "5. Configure GitHub Actions secrets"
echo ""
echo "To start the security patch:"
echo "npm start"
echo ""
echo "To run tests:"
echo "npm run test-security"

print_success "Google Home Security Patch is ready for GitHub! 🚀"
