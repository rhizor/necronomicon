#!/usr/bin/env python3
"""
Necronomicon SIEM - Main Entry Point

The Book of the Dead - Unifying All Forbidden Knowledge

Usage:
    python -m necronomicon
    
Or:
    from necronomicon import SIEMAPI
    api = SIEMAPI()
    api.start()
"""

import sys
from necronomicon.api import SIEMAPI


def main():
    """Main entry point"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                    📖 NECRONOMICON SIEM 📖                      ║
║                                                                  ║
║  "That is not dead which can eternal lie,                        ║
║   And with strange aeons even death may die."                    ║
║                                           - H.P. Lovecraft       ║
╠══════════════════════════════════════════════════════════════════╣
║  Unifying:                                                       ║
║    🎯 Arkham (CTF Agent)                                          ║
║    🛡️ Providence SOC                                             ║
║    ⚔️ Security Enforcer                                            ║
║    🔮 Azathoth TI                                                 ║
║    🎭 R'lyeh Honeypot                                            ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    api = SIEMAPI(host='0.0.0.0', port=7000)
    
    try:
        api.start()
    except KeyboardInterrupt:
        print("\n👋 Necronomicon shutting down...")
        sys.exit(0)


if __name__ == '__main__':
    main()
