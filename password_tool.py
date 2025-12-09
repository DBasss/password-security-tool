import re
import string
import secrets
import hashlib
import argparse
from datetime import datetime

class PasswordTool:
    """A tool for checking password strength and generating secure passwords."""
    
    # Common weak passwords list (sample)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', 
        '1234567', 'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
        'master', 'Password123!', 'kevin', 'FNAF', 'shadow', 'punisher', 'football',
        'password1', 'password123', '123456789', '12345', '1234', '111111',
        '0987654321', 'asdasdasd', '321654987', 'vwvwvwvwvw', 'Pass', 'Word'
    }
    
    def __init__(self):
        self.log_file = f'password_tool_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    
    def log(self, message):
        """Log messages to console and file."""
        print(message)
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    
    def check_strength(self, password):
        self.log(f"\n=== Password Strength Analysis ===")
        
        score = 0
        feedback = []
        
        # Check length
        length = len(password)
        if length < 8:
            feedback.append("- Too short (minimum 8 characters recommended)")
        elif length >= 8 and length < 12:
            score += 1
            feedback.append("-  Adequate length (8-11 characters)")
        elif length >= 12 and length < 16:
            score += 2
            feedback.append("+ Good length (12-15 characters)")
        else:
            score += 3
            feedback.append("+ Excellent length (16+ characters)")
        
        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            score += 1
            feedback.append("+ Contains lowercase letters")
        else:
            feedback.append("- Missing lowercase letters")
        
        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            score += 1
            feedback.append("+ Contains uppercase letters")
        else:
            feedback.append("- Missing uppercase letters")
        
        # Check for digits
        if re.search(r'\d', password):
            score += 1
            feedback.append("+ Contains numbers")
        else:
            feedback.append("- Missing numbers")
        
        # Check for special characters
        if re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/;`~]', password):
            score += 2
            feedback.append("+ Contains special characters")
        else:
            feedback.append("- Missing special characters")
        
        # Check for common passwords
        if password.lower() in self.COMMON_PASSWORDS:
            score = 0  # Override score to 0 for common passwords
            feedback.append("-  WARNING: This is a commonly used password!")
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            score -= 1
            feedback.append("-  Contains repeated characters (e.g., 'aaa', '111')")
        
        # Check for sequential characters
        if self._has_sequential_chars(password):
            score -= 1
            feedback.append("-  Contains sequential characters (e.g., 'abc', '123')")
        
        # Overall strength
        if score <= 2:
            strength = "WEAK X"
            recommendation = "This password is vulnerable. Generate a stronger one!"
        elif score <= 5:
            strength = "MODERATE ~"
            recommendation = "This password is okay but could be stronger."
        elif score <= 7:
            strength = "STRONG :)"
            recommendation = "This is a good password!"
        else:
            strength = "VERY STRONG >:)"
            recommendation = "Excellent password!"
        
        # Display results
        self.log(f"Password Length: {length} characters")
        self.log(f"Strength Score: {max(0, score)}/10")
        self.log(f"Overall Strength: {strength}")
        self.log(f"\nDetails:")
        for item in feedback:
            self.log(f"  {item}")
        self.log(f"\nRecommendation: {recommendation}")
        
        return {
            'score': max(0, score),
            'strength': strength,
            'feedback': feedback,
            'recommendation': recommendation
        }
    
    def _has_sequential_chars(self, password):
        """Check if password contains sequential characters."""
        sequences = ['abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij', 
                    'ijk', 'jkl', 'klm', 'lmn', 'mno', 'nop', 'opq', 'pqr',
                    'qrs', 'rst', 'stu', 'tuv', 'uvw', 'vwx', 'wxy', 'xyz',
                    '012', '123', '234', '345', '456', '567', '678', '789']
        
        password_lower = password.lower()
        return any(seq in password_lower for seq in sequences)
    
    def generate_password(self, length=16, use_uppercase=True, use_lowercase=True, 
                         use_digits=True, use_special=True, exclude_ambiguous=False):
        """Generate a secure random password."""
        
        if length < 8:
            self.log("Warning: Password length should be at least 8 characters. Setting to 8.")
            length = 8
        
        # Build character pool
        chars = ''
        if use_lowercase:
            chars += string.ascii_lowercase
        if use_uppercase:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            ambiguous = 'il1Lo0O'
            chars = ''.join(c for c in chars if c not in ambiguous)
        
        if not chars:
            self.log("Error: No character types selected!")
            return None
        
        # Generate password ensuring at least one char from each selected type
        password = []
        
        if use_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if use_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            password.append(secrets.choice(string.digits))
        if use_special:
            password.append(secrets.choice('!@#$%^&*()_+-=[]{}|;:,.<>?'))
        
        # Fill remaining length
        for _ in range(length - len(password)):
            password.append(secrets.choice(chars))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        generated_password = ''.join(password)
        
        self.log(f"\n=== Generated Password ===")
        self.log(f"Password: {generated_password}")
        self.log(f"Length: {len(generated_password)} characters")
        self.log(f"Settings: Uppercase={use_uppercase}, Lowercase={use_lowercase}, "
                f"Digits={use_digits}, Special={use_special}")
        
        return generated_password
    
    def generate_passphrase(self, num_words=4):
        """Generate a memorable passphrase using random words."""
        # Sample word list (in real implementation, use a larger dictionary)
        word_list = [
            'apple', 'mountain', 'river', 'cloud', 'forest', 'ocean', 'tiger',
            'dragon', 'phoenix', 'castle', 'bridge', 'garden', 'temple', 'star',
            'moon', 'sun', 'wind', 'fire', 'water', 'earth', 'thunder', 'storm',
            'crystal', 'diamond', 'silver', 'golden', 'shadow', 'light', 'dream',
            'wisdom', 'courage', 'harmony', 'freedom', 'journey', 'adventure',
            'mystery', 'legend', 'magic', 'spirit', 'energy', 'power', 'force',
            'knight', 'wizard', 'warrior', 'hunter', 'sailor', 'pilot', 'explorer'
        ]
        
        words = [secrets.choice(word_list).capitalize() for _ in range(num_words)]
        # Add random numbers and special char
        number = str(secrets.randbelow(100))
        special = secrets.choice('!@#$%^&*')
        
        passphrase = '-'.join(words) + number + special
        
        self.log(f"\n=== Generated Passphrase ===")
        self.log(f"Passphrase: {passphrase}")
        self.log(f"Length: {len(passphrase)} characters")
        self.log(f"Note: Passphrases are easier to remember!")
        
        return passphrase
    
    def check_breach(self, password):
        """Check if password hash appears in common breached password databases (simplified)."""
        # This is a simplified version. Real implementation would use haveibeenpwned API
        self.log(f"\n=== Breach Check (Simulated) ===")
        
        # Calculate SHA-1 hash (what haveibeenpwned uses)
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        
        self.log(f"Password SHA-1 Hash: {sha1_hash}")
        self.log(f"Note: In production, this would check against haveibeenpwned.com API")
        
        # Check against our common passwords list
        if password.lower() in self.COMMON_PASSWORDS:
            self.log("⚠️  WARNING: This password is in common breach databases!")
            self.log("Recommendation: Choose a different password immediately.")
            return True
        else:
            self.log("✓ Password not found in local common password database")
            self.log("Note: This is a limited check. For full verification, use haveibeenpwned.com")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Password Strength Checker & Generator Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""

 
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Check command
    check_parser = subparsers.add_parser('check', help='Check password strength')
    check_parser.add_argument('password', help='Password to check')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate secure password')
    gen_parser.add_argument('--length', type=int, default=16, help='Password length (default: 16)')
    gen_parser.add_argument('--no-uppercase', action='store_true', help='Exclude uppercase letters')
    gen_parser.add_argument('--no-lowercase', action='store_true', help='Exclude lowercase letters')
    gen_parser.add_argument('--no-digits', action='store_true', help='Exclude digits')
    gen_parser.add_argument('--no-special', action='store_true', help='Exclude special characters')
    gen_parser.add_argument('--exclude-ambiguous', action='store_true', 
                           help='Exclude ambiguous characters (il1Lo0O)')
    
    # Passphrase command
    pass_parser = subparsers.add_parser('passphrase', help='Generate memorable passphrase')
    pass_parser.add_argument('--words', type=int, default=4, help='Number of words (default: 4)')
    
    # Breach check command
    breach_parser = subparsers.add_parser('breach', help='Check if password is breached')
    breach_parser.add_argument('password', help='Password to check')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    tool = PasswordTool()
    
    if args.command == 'check':
        tool.check_strength(args.password)
    
    elif args.command == 'generate':
        password = tool.generate_password(
            length=args.length,
            use_uppercase=not args.no_uppercase,
            use_lowercase=not args.no_lowercase,
            use_digits=not args.no_digits,
            use_special=not args.no_special,
            exclude_ambiguous=args.exclude_ambiguous
        )
        if password:
            # Also check its strength
            print("\n" + "="*50)
            tool.check_strength(password)
    
    elif args.command == 'passphrase':
        passphrase = tool.generate_passphrase(num_words=args.words)
        # Also check its strength
        print("\n" + "="*50)
        tool.check_strength(passphrase)
    
    elif args.command == 'breach':
        tool.check_breach(args.password)


if __name__ == '__main__':
    main()