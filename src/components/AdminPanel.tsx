import { useState, useEffect, useCallback, type FormEvent } from 'react';
import { X, Plus, Loader2, Users, Building2, AlertCircle, Trash2, Shield, UserCog, Eye, KeyRound, Rss } from 'lucide-react';
import ApiKeysPanel from './ApiKeysPanel';
import FeedsPanel from './FeedsPanel';
import { cn } from '@/lib/utils';
import * as api from '@/lib/api';
import ConfirmDialog from './ConfirmDialog';
import type { UserRecord, TeamDetail, TeamRecord, UserRole } from '@/types';

interface Props {
  open: boolean;
  onClose: () => void;
}

const ROLE_LABELS: Record<string, string> = { admin: 'Admin', analyst: 'Analyst', viewer: 'Viewer' };
const ROLE_COLORS: Record<string, string> = {
  admin: 'text-red-400 bg-red-500/10 border-red-500/20',
  analyst: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
  viewer: 'text-muted-foreground bg-secondary/50 border-border',
};

type Tab = 'users' | 'teams' | 'apikeys' | 'feeds';

export default function AdminPanel({ open, onClose }: Props) {
  const [tab, setTab] = useState<Tab>('users');
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [teams, setTeams] = useState<TeamRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Create user form
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [newEmail, setNewEmail] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('analyst');
  const [creating, setCreating] = useState(false);

  // Create team form
  const [showCreateTeam, setShowCreateTeam] = useState(false);
  const [newTeamName, setNewTeamName] = useState('');
  const [newTeamDesc, setNewTeamDesc] = useState('');
  const [creatingTeam, setCreatingTeam] = useState(false);

  // Team detail
  const [selectedTeam, setSelectedTeam] = useState<TeamDetail | null>(null);

  // Add member to team
  const [addMemberUserId, setAddMemberUserId] = useState('');
  const [addMemberRole, setAddMemberRole] = useState('member');
  const [addingMember, setAddingMember] = useState(false);

  // Reset password
  const [resetPasswordUserId, setResetPasswordUserId] = useState<string | null>(null);
  const [resetNewPassword, setResetNewPassword] = useState('');
  const [resettingPassword, setResettingPassword] = useState(false);

  const loadUsers = useCallback(async () => {
    try { setUsers(await api.fetchUsers() as UserRecord[]); } catch { /* ignore */ }
  }, []);

  const loadTeams = useCallback(async () => {
    try { setTeams(await api.fetchTeams()); } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    setError(null);
    Promise.all([loadUsers(), loadTeams()]).finally(() => setLoading(false));
  }, [open, loadUsers, loadTeams]);

  const handleCreateUser = async (e: FormEvent) => {
    e.preventDefault();
    setCreating(true);
    setError(null);
    try {
      await api.createUser({ email: newEmail, password: newPassword, displayName: newDisplayName, role: newRole });
      setShowCreateUser(false);
      setNewEmail(''); setNewDisplayName(''); setNewPassword(''); setNewRole('analyst');
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user');
    } finally {
      setCreating(false);
    }
  };

  const handleToggleDisable = async (user: UserRecord) => {
    try {
      if (user.disabled) {
        await api.updateUser(user.id, { disabled: false });
      } else {
        await api.disableUser(user.id);
      }
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update user');
    }
  };

  const handleRoleChange = async (userId: string, role: string) => {
    try {
      await api.updateUser(userId, { role });
      await loadUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role');
    }
  };

  const handleResetPassword = async (e: FormEvent) => {
    e.preventDefault();
    if (!resetPasswordUserId || resetNewPassword.length < 8) return;
    setResettingPassword(true);
    try {
      await api.resetUserPassword(resetPasswordUserId, resetNewPassword);
      setResetPasswordUserId(null);
      setResetNewPassword('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Password reset failed');
    } finally {
      setResettingPassword(false);
    }
  };

  const handleCreateTeam = async (e: FormEvent) => {
    e.preventDefault();
    setCreatingTeam(true);
    setError(null);
    try {
      await api.createTeam({ name: newTeamName, description: newTeamDesc });
      setShowCreateTeam(false);
      setNewTeamName(''); setNewTeamDesc('');
      await loadTeams();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create team');
    } finally {
      setCreatingTeam(false);
    }
  };

  const handleViewTeam = async (teamId: string) => {
    try {
      const detail = await api.fetchTeamDetail(teamId);
      setSelectedTeam(detail);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load team');
    }
  };

  const [confirmDeleteTeamId, setConfirmDeleteTeamId] = useState<string | null>(null);

  const handleDeleteTeam = async (teamId: string) => {
    try {
      await api.deleteTeam(teamId);
      setSelectedTeam(null);
      await loadTeams();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete team');
    }
  };

  const handleAddMember = async (e: FormEvent) => {
    e.preventDefault();
    if (!selectedTeam || !addMemberUserId) return;
    setAddingMember(true);
    try {
      await api.addTeamMember(selectedTeam.id, addMemberUserId, addMemberRole);
      setAddMemberUserId(''); setAddMemberRole('member');
      const detail = await api.fetchTeamDetail(selectedTeam.id);
      setSelectedTeam(detail);
      await loadTeams();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add member');
    } finally {
      setAddingMember(false);
    }
  };

  const handleRemoveMember = async (userId: string) => {
    if (!selectedTeam) return;
    try {
      await api.removeTeamMember(selectedTeam.id, userId);
      const detail = await api.fetchTeamDetail(selectedTeam.id);
      setSelectedTeam(detail);
      await loadTeams();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove member');
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-navy-900 border border-border rounded-lg w-full max-w-2xl max-h-[85vh] shadow-xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border flex-shrink-0">
          <div className="flex items-center gap-3">
            <h2 className="text-sm font-semibold text-foreground">Admin Panel</h2>
            <div className="flex gap-1">
              <button
                onClick={() => { setTab('users'); setSelectedTeam(null); }}
                className={cn(
                  'px-2.5 py-1 text-xs rounded-md transition-colors',
                  tab === 'users' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-muted-foreground hover:text-foreground'
                )}
              >
                <Users className="w-3 h-3 inline mr-1" />Users
              </button>
              <button
                onClick={() => { setTab('teams'); setSelectedTeam(null); }}
                className={cn(
                  'px-2.5 py-1 text-xs rounded-md transition-colors',
                  tab === 'teams' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-muted-foreground hover:text-foreground'
                )}
              >
                <Building2 className="w-3 h-3 inline mr-1" />Teams
              </button>
              <button
                onClick={() => { setTab('apikeys'); setSelectedTeam(null); }}
                className={cn(
                  'px-2.5 py-1 text-xs rounded-md transition-colors',
                  tab === 'apikeys' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-muted-foreground hover:text-foreground'
                )}
              >
                <KeyRound className="w-3 h-3 inline mr-1" />API Keys
              </button>
              <button
                onClick={() => { setTab('feeds'); setSelectedTeam(null); }}
                className={cn(
                  'px-2.5 py-1 text-xs rounded-md transition-colors',
                  tab === 'feeds' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-muted-foreground hover:text-foreground'
                )}
              >
                <Rss className="w-3 h-3 inline mr-1" />Threat Feeds
              </button>
            </div>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {error && (
          <div className="mx-4 mt-3 flex items-start gap-2 text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-md px-3 py-2">
            <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
            <button onClick={() => setError(null)} className="ml-auto text-red-400/60 hover:text-red-400"><X className="w-3 h-3" /></button>
          </div>
        )}

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-4">
          {loading ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground text-xs">
              <Loader2 className="w-4 h-4 animate-spin mr-2" />Loading…
            </div>
          ) : tab === 'users' ? (
            <div className="space-y-3">
              {/* Create user */}
              {!showCreateUser ? (
                <button
                  onClick={() => setShowCreateUser(true)}
                  className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  <Plus className="w-3 h-3" />Create User
                </button>
              ) : (
                <form onSubmit={handleCreateUser} className="bg-secondary/30 border border-border rounded-md p-3 space-y-2">
                  <div className="grid grid-cols-2 gap-2">
                    <input value={newEmail} onChange={(e) => setNewEmail(e.target.value)} placeholder="Email" type="email" required
                      className="bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50" />
                    <input value={newDisplayName} onChange={(e) => setNewDisplayName(e.target.value)} placeholder="Display Name" required
                      className="bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50" />
                    <input value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="Password (min 8)" type="password" required minLength={8}
                      className="bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50" />
                    <select value={newRole} onChange={(e) => setNewRole(e.target.value as UserRole)}
                      className="bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50">
                      <option value="analyst">Analyst</option>
                      <option value="viewer">Viewer</option>
                      <option value="admin">Admin</option>
                    </select>
                  </div>
                  <div className="flex gap-2 justify-end">
                    <button type="button" onClick={() => setShowCreateUser(false)} className="px-2.5 py-1 text-xs text-muted-foreground border border-border rounded">Cancel</button>
                    <button type="submit" disabled={creating} className="px-2.5 py-1 text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded flex items-center gap-1">
                      {creating && <Loader2 className="w-3 h-3 animate-spin" />}Create
                    </button>
                  </div>
                </form>
              )}

              {/* Reset password inline */}
              {resetPasswordUserId && (
                <form onSubmit={handleResetPassword} className="bg-secondary/30 border border-border rounded-md p-3 flex gap-2 items-end">
                  <div className="flex-1">
                    <label className="text-[10px] text-muted-foreground">New password for {users.find(u => u.id === resetPasswordUserId)?.email}</label>
                    <input value={resetNewPassword} onChange={(e) => setResetNewPassword(e.target.value)} type="password" placeholder="Min 8 characters" minLength={8}
                      className="w-full bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50 mt-1" autoFocus />
                  </div>
                  <button type="button" onClick={() => { setResetPasswordUserId(null); setResetNewPassword(''); }} className="px-2.5 py-1.5 text-xs text-muted-foreground border border-border rounded">Cancel</button>
                  <button type="submit" disabled={resettingPassword || resetNewPassword.length < 8} className="px-2.5 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded flex items-center gap-1">
                    {resettingPassword && <Loader2 className="w-3 h-3 animate-spin" />}Reset
                  </button>
                </form>
              )}

              {/* User list */}
              <div className="space-y-1">
                {users.map((user) => (
                  <div key={user.id} className={cn('flex items-center gap-3 px-3 py-2.5 rounded-md border', user.disabled ? 'opacity-50 border-border' : 'border-transparent hover:bg-secondary/30')}>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium text-foreground truncate">{user.displayName}</span>
                        <span className={cn('text-[10px] px-1.5 py-0.5 rounded border', ROLE_COLORS[user.role])}>
                          {ROLE_LABELS[user.role]}
                        </span>
                        {user.disabled && <span className="text-[10px] text-red-400">(disabled)</span>}
                      </div>
                      <div className="text-[10px] text-muted-foreground">{user.email}</div>
                      {user.teams.length > 0 && (
                        <div className="flex gap-1 mt-0.5 flex-wrap">
                          {user.teams.map((t) => (
                            <span key={t.id} className="text-[9px] px-1 py-0 bg-secondary/50 border border-border rounded text-muted-foreground">{t.name}</span>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <select
                        value={user.role}
                        onChange={(e) => handleRoleChange(user.id, e.target.value)}
                        className="bg-secondary/50 border border-border rounded px-1.5 py-0.5 text-[10px] text-foreground"
                      >
                        <option value="admin">Admin</option>
                        <option value="analyst">Analyst</option>
                        <option value="viewer">Viewer</option>
                      </select>
                      <button
                        onClick={() => { setResetPasswordUserId(user.id); setResetNewPassword(''); }}
                        className="p-1 text-muted-foreground hover:text-foreground rounded transition-colors"
                        title="Reset password"
                      >
                        <UserCog className="w-3 h-3" />
                      </button>
                      <button
                        onClick={() => handleToggleDisable(user)}
                        className={cn('p-1 rounded transition-colors', user.disabled ? 'text-green-400 hover:text-green-300' : 'text-red-400/60 hover:text-red-400')}
                        title={user.disabled ? 'Enable user' : 'Disable user'}
                      >
                        {user.disabled ? <Shield className="w-3 h-3" /> : <Trash2 className="w-3 h-3" />}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : tab === 'apikeys' ? (
            <ApiKeysPanel />
          ) : tab === 'feeds' ? (
            <FeedsPanel />
          ) : /* teams tab */ selectedTeam ? (
            /* Team detail view */
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <button onClick={() => setSelectedTeam(null)} className="text-xs text-cyan-400 hover:text-cyan-300">← Back</button>
                <h3 className="text-sm font-semibold text-foreground">{selectedTeam.name}</h3>
              </div>
              {selectedTeam.description && (
                <p className="text-xs text-muted-foreground">{selectedTeam.description}</p>
              )}

              {/* Add member */}
              <form onSubmit={handleAddMember} className="flex gap-2 items-end">
                <div className="flex-1">
                  <label className="text-[10px] text-muted-foreground">Add Member</label>
                  <select value={addMemberUserId} onChange={(e) => setAddMemberUserId(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground mt-1">
                    <option value="">Select user…</option>
                    {users
                      .filter((u) => !u.disabled && !selectedTeam.members.some((m) => m.userId === u.id))
                      .map((u) => <option key={u.id} value={u.id}>{u.displayName} ({u.email})</option>)
                    }
                  </select>
                </div>
                <select value={addMemberRole} onChange={(e) => setAddMemberRole(e.target.value)}
                  className="bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground">
                  <option value="member">Member</option>
                  <option value="lead">Lead</option>
                </select>
                <button type="submit" disabled={addingMember || !addMemberUserId}
                  className="px-2.5 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded flex items-center gap-1">
                  {addingMember && <Loader2 className="w-3 h-3 animate-spin" />}Add
                </button>
              </form>

              {/* Members list */}
              <div className="space-y-1">
                {selectedTeam.members.map((m) => (
                  <div key={m.userId} className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-secondary/30">
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-medium text-foreground">{m.displayName}</div>
                      <div className="text-[10px] text-muted-foreground">{m.email} · {m.teamRole}</div>
                    </div>
                    <button onClick={() => handleRemoveMember(m.userId)} className="p-1 text-red-400/60 hover:text-red-400 rounded transition-colors" title="Remove">
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                ))}
                {selectedTeam.members.length === 0 && (
                  <div className="text-xs text-muted-foreground text-center py-4">No members yet</div>
                )}
              </div>

              <button onClick={() => setConfirmDeleteTeamId(selectedTeam.id)} className="text-xs text-red-400 hover:text-red-300 transition-colors">
                Delete Team
              </button>
            </div>
          ) : (
            /* Teams list */
            <div className="space-y-3">
              {!showCreateTeam ? (
                <button onClick={() => setShowCreateTeam(true)} className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
                  <Plus className="w-3 h-3" />Create Team
                </button>
              ) : (
                <form onSubmit={handleCreateTeam} className="bg-secondary/30 border border-border rounded-md p-3 space-y-2">
                  <input value={newTeamName} onChange={(e) => setNewTeamName(e.target.value)} placeholder="Team Name" required
                    className="w-full bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50" />
                  <input value={newTeamDesc} onChange={(e) => setNewTeamDesc(e.target.value)} placeholder="Description (optional)"
                    className="w-full bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50" />
                  <div className="flex gap-2 justify-end">
                    <button type="button" onClick={() => setShowCreateTeam(false)} className="px-2.5 py-1 text-xs text-muted-foreground border border-border rounded">Cancel</button>
                    <button type="submit" disabled={creatingTeam} className="px-2.5 py-1 text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded flex items-center gap-1">
                      {creatingTeam && <Loader2 className="w-3 h-3 animate-spin" />}Create
                    </button>
                  </div>
                </form>
              )}

              <div className="space-y-1">
                {teams.map((team) => (
                  <div key={team.id} className="flex items-center gap-3 px-3 py-2.5 rounded-md border border-transparent hover:bg-secondary/30 cursor-pointer" onClick={() => handleViewTeam(team.id)}>
                    <Building2 className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-medium text-foreground">{team.name}</div>
                      {team.description && <div className="text-[10px] text-muted-foreground truncate">{team.description}</div>}
                    </div>
                    <span className="text-[10px] text-muted-foreground flex-shrink-0">{team.memberCount} members</span>
                    <Eye className="w-3 h-3 text-muted-foreground/50" />
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={!!confirmDeleteTeamId}
        title="Delete team?"
        message="Only teams with zero sessions can be deleted. This cannot be undone."
        confirmLabel="Delete"
        danger
        onConfirm={() => {
          if (confirmDeleteTeamId) handleDeleteTeam(confirmDeleteTeamId);
          setConfirmDeleteTeamId(null);
        }}
        onCancel={() => setConfirmDeleteTeamId(null)}
      />
    </div>
  );
}
