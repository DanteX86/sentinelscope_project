# SentinelScope

A comprehensive security analysis and malware detection tool built with Python and YARA rules, featuring an intuitive GUI interface.

## 🚀 Features

### Core Security Features
- **Advanced YARA Rules Engine**: Comprehensive malware detection with multiple rule categories
- **Multi-Scan Types**: Support for single files, directories, and entire devices/drives
- **Real-time Threat Detection**: Identifies ransomware, keyloggers, web shells, trojans, and more
- **Anti-Evasion Detection**: Detects anti-VM and sandbox evasion techniques

### Enhanced Detection Capabilities
- **Suspicious PE Headers**: Detects packed executables and suspicious binaries
- **Network Activity Monitoring**: Identifies suspicious network communication patterns
- **Cryptocurrency Mining Detection**: Finds hidden mining software
- **Password Harvesting Detection**: Identifies credential theft attempts
- **Web Shell Detection**: Discovers malicious web scripts

### User Experience
- **Intuitive GUI**: Easy-to-use tkinter-based interface
- **File Type Filtering**: Scan specific file types (executables, scripts, documents, etc.)
- **Configurable Options**: Recursive scanning, file size limits, clean file display
- **Progress Tracking**: Real-time scan progress with cancellation support
- **Results Export**: Export scan results to JSON format with metadata

## 📁 Project Structure

- `sentinelscope_app.py` - Main GUI application
- `rules.yar` - Comprehensive YARA rules for malware detection
- `config.json` - Configuration settings for the application
- `requirements.txt` - Python dependencies
- `test_core.py` - Core functionality tests
- `test_sentinelscope.py` - Application integration tests
- `README.md` - This documentation

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/DanteX86/sentinelscope_project.git
   cd sentinelscope_project
   ```

2. **Install required dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify YARA installation**:
   ```bash
   python -c "import yara; print('YARA is ready!')"
   ```

## 🎯 Usage

### Running the Application
```bash
python sentinelscope_app.py
```

### Scan Types
- **Single File**: Analyze a specific file for threats
- **Directory**: Scan all files in a directory (with optional recursion)
- **Device/Drive**: Comprehensive scan of entire drives or mounted devices

### File Type Filters
- **All Files**: Scan everything (default)
- **Executables**: .exe, .dll, .so, .dylib, .app files
- **Scripts**: .py, .js, .php, .sh, .bat, .cmd, .ps1 files
- **Documents**: .pdf, .doc, .docx, .xls, .xlsx, .ppt, .pptx files
- **Archives**: .zip, .rar, .7z, .tar, .gz, .bz2 files
- **Images**: .jpg, .jpeg, .png, .gif, .bmp, .tiff files

### Export Options
- Export scan results to JSON format
- Includes scan metadata, settings, and timestamp
- Structured data for further analysis or reporting

## 🧪 Testing

Run the comprehensive test suite:
```bash
# Run core functionality tests
python test_core.py

# Run application integration tests
python test_sentinelscope.py
```

## ⚙️ Configuration

Edit `config.json` to customize:
- Default scan settings
- File size limits
- UI preferences
- Export settings

## 🔒 Security Features

### YARA Rules Categories
1. **Suspicious Executables** - PE header analysis
2. **Potential Malware** - System tool abuse detection
3. **Suspicious Scripts** - Obfuscated script detection
4. **Network Activity** - Suspicious communication patterns
5. **Password Harvesting** - Credential theft detection
6. **Cryptocurrency Miners** - Hidden mining software
7. **Ransomware Patterns** - Encryption malware detection
8. **Web Shells** - Malicious web script detection
9. **Keyloggers** - Keystroke capture detection
10. **Network Tools** - Backdoor and reverse shell detection
11. **Anti-VM Detection** - Sandbox evasion techniques

## 🚨 Threat Severity Levels

- **🔴 Critical**: Immediate action required (e.g., ransomware)
- **🟠 High**: Serious threats requiring attention (e.g., keyloggers, web shells)
- **🟡 Medium**: Potentially unwanted programs (e.g., suspicious executables)

## 📊 Version Control Integration

This project uses Git for version control with the following workflow:
- `master` branch: Stable releases
- `feature/*` branches: New feature development
- `bugfix/*` branches: Bug fixes

## 🤝 Contributing

1. Create a feature branch: `git checkout -b feature/new-feature`
2. Make your changes and commit: `git commit -am 'Add new feature'`
3. Push to the branch: `git push origin feature/new-feature`
4. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

SentinelScope is for educational and legitimate security research purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems or files.
