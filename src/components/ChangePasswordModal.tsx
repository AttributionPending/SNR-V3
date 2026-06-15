import { useState, type FormEvent } from 'react';
import { X, Loader2, AlertCircle, CheckCircle, Eye, EyeOff } from 'lucide-react';
import * as api from '@/lib/api';

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function ChangePasswordModal({ open, onClose }: Props) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPasswords, setShowPasswords] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const reset = () => {
    setCurrentPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setError(null);
    setSuccess(false);
    setShowPasswords(false);
  };

  const handleClose = () => {
    reset();
    onClose();
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (newPassword.length < 10) {
      setError('New password must be at least 10 characters');
      return;
    }
    if (!/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/\d/.test(newPassword) || !/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(newPassword)) {
      setError('Password must include uppercase, lowercase, number, and special character');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await api.changePassword(currentPassword, newPassword);
      setSuccess(true);
      setTimeout(handleClose, 1500);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Password change failed');
    } finally {
      setLoading(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-navy-900 border border-border rounded-lg w-full max-w-sm shadow-xl">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <h2 className="text-sm font-semibold text-foreground">Change Password</h2>
          <button onClick={handleClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-3">
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Current Password</label>
            <input
              type={showPasswords ? 'text' : 'password'}
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-md px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
              disabled={loading || success}
              autoFocus
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">New Password</label>
            <input
              type={showPasswords ? 'text' : 'password'}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-md px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
              disabled={loading || success}
            />
          </div>
          <div>
            <label className="block text-xs text-muted-foreground mb-1">Confirm New Password</label>
            <input
              type={showPasswords ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full bg-secondary/50 border border-border rounded-md px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
              disabled={loading || success}
            />
          </div>

          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
            <input
              type="checkbox"
              checked={showPasswords}
              onChange={(e) => setShowPasswords(e.target.checked)}
              className="rounded border-border"
            />
            Show passwords
          </label>

          {error && (
            <div className="flex items-start gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-md px-3 py-2">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="flex items-center gap-2 text-xs text-green-400 bg-green-500/10 border border-green-500/20 rounded-md px-3 py-2">
              <CheckCircle className="w-3.5 h-3.5" />
              Password changed successfully
            </div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={handleClose}
              className="px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground border border-border rounded-md transition-colors"
              disabled={loading}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || success || !currentPassword || !newPassword || !confirmPassword}
              className="px-3 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-md transition-colors flex items-center gap-1.5"
            >
              {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : null}
              {loading ? 'Changing…' : 'Change Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
