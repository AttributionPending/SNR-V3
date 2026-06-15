import { useState, type FormEvent } from 'react';
import { Loader2, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';

export default function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password) return;
    setLoading(true);
    setError(null);
    try {
      await login(email.trim(), password);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        {/* Logo — waveform wordmark */}
        <div className="flex flex-col items-center mb-8">
          <svg viewBox="0 0 520 120" className="w-64 h-auto mb-2" aria-label="SNR — Signal to Noise">
            <defs>
              <linearGradient id="loginLogoGrad" x1="0%" y1="50%" x2="100%" y2="50%">
                <stop offset="0%" stopColor="#2563eb"/>
                <stop offset="35%" stopColor="#06b6d4"/>
                <stop offset="70%" stopColor="#22d3ee"/>
                <stop offset="100%" stopColor="#34d399"/>
              </linearGradient>
            </defs>
            {/* Waveform */}
            <path
              d="M 10 60 Q 30 60 45 42 Q 58 26 70 35 Q 80 42 88 16 L 105 95 Q 112 115 125 70 Q 135 38 150 48 Q 162 56 172 50 L 190 60"
              fill="none"
              stroke="url(#loginLogoGrad)"
              strokeWidth="8"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            {/* SNR text */}
            <text
              x="205"
              y="78"
              fill="url(#loginLogoGrad)"
              fontFamily="system-ui, -apple-system, 'Segoe UI', sans-serif"
              fontWeight="800"
              fontSize="72"
              letterSpacing="4"
            >SNR</text>
          </svg>
          <p className="text-xs text-muted-foreground uppercase tracking-[0.25em]">
            Signal to Noise
          </p>
        </div>

        {/* Login form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="bg-navy-900 border border-border rounded-lg p-6 space-y-4">
            <div>
              <label htmlFor="login-email" className="block text-xs font-medium text-muted-foreground mb-1.5">
                Email
              </label>
              <input
                id="login-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@org.com"
                autoComplete="email"
                autoFocus
                className="w-full bg-secondary/50 border border-border rounded-md px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 focus:border-cyan-500/50 transition-colors"
                disabled={loading}
              />
            </div>

            <div>
              <label htmlFor="login-password" className="block text-xs font-medium text-muted-foreground mb-1.5">
                Password
              </label>
              <div className="relative">
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  className="w-full bg-secondary/50 border border-border rounded-md px-3 py-2 pr-9 text-sm text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 focus:border-cyan-500/50 transition-colors"
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground/50 hover:text-foreground transition-colors"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-md px-3 py-2">
                <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading || !email.trim() || !password}
              className="w-full h-9 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  Signing in…
                </>
              ) : (
                'Sign in'
              )}
            </button>
          </div>
        </form>

        <p className="text-[10px] text-muted-foreground/30 text-center mt-6">
          SNR — Signal to Noise
        </p>
      </div>
    </div>
  );
}
