AICodeAuditor v1.0

A multi-language code security auditing tool developed by 信安西部 - 明镜高悬实验室 (Westsec - Mingjing Gaoxuan Laboratory), designed to detect potential security vulnerabilities in source code through static analysis.
Features

    Supports supports multiple programming languages: Python, JavaScript, Java, PHP, C, C++, Go, Ruby, HTML, etc.
    Dual detection mechanisms: rule-based static analysis and optional API-enhanced detection
    User-friendly graphical interface
    Configurable scanning rules and whitelisting
    Multi-threaded processing for efficient code auditing
    Detailed vulnerability reporting with code snippets and remediation suggestions
    Progress tracking and status updates
    Exportable audit reports
    Plugin support for extended functionality

Supported Vulnerabilities

AICodeAuditor can detect various common security vulnerabilities, including but not limited to:

    SQL injection risks
    Cross-site scripting (XSS) vulnerabilities
    Code injection risks
    Command injection vulnerabilities
    Deserialization vulnerabilities
    Path traversal risks
    Buffer overflow risks
    Format string vulnerabilities
    File inclusion vulnerabilities

Installation

    Ensure you have Python 3.x installed on your system
    Clone or download this repository
    Install required dependencies (if any specific dependencies are needed)

Usage

    Run the application：
    
    python AI-Code-Auditor-v1.0.py

    Basic workflow:
        Click "选择项目" (Select Project) to choose the directory containing your source code
        Click "开始审计" (Start Audit) to begin the code scanning process
        View results in the right panel
        Click on any result to see detailed information and code snippets
        Use "暂停" (Pause) or "停止" (Stop) to control the auditing process
        Export results using "导出报告" (Export Report)
    Advanced features:
        "导入规则" (Import Rules): Load custom security rules from JSON files
        "API 设置" (API Settings): Configure external API for enhanced detection capabilities

Configuration

The tool uses a configuration file AICodeAuditor.ini with the following settings:

    API key and endpoint for enhanced detection
    Maximum number of threads
    Large file threshold (in MB)
    Maximum recursion depth for directory scanning

Custom Rules

You can import custom security rules in JSON format. Each rule should follow this structure:

[
    {
        "lang": "language_name",
        "pattern": "regular_expression_pattern",
        "description": "Vulnerability description"
    }
]

Logging

Audit logs are stored in the logs directory, with a maximum size of 5MB per file and up to 3 backup logs retained.

Plugins

The tool supports plugins located in the plugins directory. Simply place your Python plugin files there, and they will be loaded automatically.

License

MIT License.
