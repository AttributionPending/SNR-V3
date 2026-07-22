import { useState, useEffect, useCallback, useRef, useMemo, lazy, Suspense } from 'react';
import { CheckCircle, XCircle, Info, X, Loader2 } from 'lucide-react';
import { TooltipProvider } from './components/ui/tooltip';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import LoginPage from './components/LoginPage';
import Sidebar from './components/Sidebar';
import WorkflowCanvas from './components/WorkflowCanvas';
import SettingsModal from './components/SettingsModal';
import { blankResult } from './lib/workbench-merge';
// Heavy full-screen overlays (reactflow / tiptap / ATT&CK dataset) — load on demand.
const EmailStudio = lazy(() => import('./components/EmailStudio'));
const Workbench = lazy(() => import('./components/Workbench'));
import ReportsModal from './components/ReportsModal';
import HelpModal from './components/HelpModal';
import ChangePasswordModal from './components/ChangePasswordModal';
import AdminPanel from './components/AdminPanel';
import KeyboardShortcutsOverlay from './components/KeyboardShortcutsOverlay';
import { useKeyboardShortcuts } from './hooks/useKeyboardShortcuts';
import { cn } from './lib/utils';
import ThreatActorView from './components/ThreatActorView';
import CaseView from './components/CaseView';
import SearchPalette from './components/SearchPalette';
import SearchView from './components/SearchView';
import IntelDashboard from './components/IntelDashboard';
import { getDefaultView } from './lib/prefs';
import { buildHash, parseHash, viewPart, sameView, type NavState, type ModalKind } from './lib/nav';
import type { AnalysisResult, AudienceType, Session, CustomAudience, ThreatActorSummary } from './types';
import * as api from './lib/api';

// ── Toast system ────────────────────────────────────────────────────────────

interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'info';
  /** Optional action button (e.g. "Undo") — clicking it dismisses the toast */
  action?: { label: string; onClick: () => void };
}

let toastCounter = 0;

const TOAST_ICONS = {
  success: <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />,
  error: <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />,
  info: <Info className="w-4 h-4 text-cyan-400 flex-shrink-0" />,
};

const TOAST_BORDER: Record<Toast['type'], string> = {
  success: 'border-green-500/30',
  error: 'border-red-500/30',
  info: 'border-cyan-500/30',
};

function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={cn(
            'flex items-start gap-2.5 px-3.5 py-2.5 rounded-lg border bg-navy-900 shadow-lg text-xs text-foreground',
            'pointer-events-auto animate-in slide-in-from-right-4 duration-200',
            TOAST_BORDER[t.type]
          )}
          style={{ maxWidth: 320 }}
        >
          {TOAST_ICONS[t.type]}
          <span className="flex-1 leading-relaxed">{t.message}</span>
          {t.action && (
            <button
              onClick={() => { t.action!.onClick(); onDismiss(t.id); }}
              className="text-cyan-400 hover:text-cyan-300 font-semibold transition-colors flex-shrink-0 underline underline-offset-2"
            >
              {t.action.label}
            </button>
          )}
          <button
            onClick={() => onDismiss(t.id)}
            className="text-muted-foreground hover:text-foreground transition-colors ml-1 flex-shrink-0"
          >
            <X className="w-3 h-3" />
          </button>
        </div>
      ))}
    </div>
  );
}

// ── App ─────────────────────────────────────────────────────────────────────

const NOTE_DEBOUNCE_MS = 800;

function AppMain() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [streamChunks, setStreamChunks] = useState('');
  const [streamPhase, setStreamPhase] = useState<1 | 2>(1);
  const [statusMessage, setStatusMessage] = useState('');
  const [sessionName, setSessionName] = useState('');
  const [audience, setAudience] = useState<string>('soc');
  const [error, setError] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [brandingStudioOpen, setBrandingStudioOpen] = useState(false);
  const [workbench, setWorkbench] = useState<{ initial: AnalysisResult; version?: number } | null>(null);
  const [reportsOpen, setReportsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);
  const [adminOpen, setAdminOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => window.innerWidth < 768);
  const [customAudiences, setCustomAudiences] = useState<CustomAudience[]>([]);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  // Threat actor grouping
  const [threatActors, setThreatActors] = useState<ThreatActorSummary[]>([]);
  const [activeThreatActorId, setActiveThreatActorId] = useState<string | null>(null);

  // Cases (investigations)
  const [cases, setCases] = useState<api.CaseSummary[]>([]);
  const [activeCaseId, setActiveCaseId] = useState<string | null>(null);

  // Global search palette + full Intelligence Search workspace + dashboard
  const [searchPaletteOpen, setSearchPaletteOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchSeed, setSearchSeed] = useState('');
  const [intelOpen, setIntelOpen] = useState(false);

  // Tags
  const [allTags, setAllTags] = useState<string[]>([]);
  const [activeTagFilters, setActiveTagFilters] = useState<string[]>([]);
  const [sessionTags, setSessionTags] = useState<string[]>([]);

  // Linked threat actor for active session
  const [linkedThreatActor, setLinkedThreatActor] = useState<{ id: string; name: string } | null>(null);

  // Status of the active session ('pending' | 'analyzing' | 'complete' | 'failed')
  const [sessionStatus, setSessionStatus] = useState<string | null>(null);

  // Raw analyst overrides for the active session (includes ioc_false_positives)
  const [analystOverrides, setAnalystOverrides] = useState<Record<string, string>>({});

  // ATT&CK diagram capture — registered by AttackChainView on mount
  const captureAttackChainRef = useRef<(() => Promise<string | null>) | null>(null);
  const handleRegisterCapture = useCallback((fn: () => Promise<string | null>) => {
    captureAttackChainRef.current = fn;
  }, []);
  const captureAttackChain = useMemo(
    () => async () => captureAttackChainRef.current?.() ?? null,
    []
  );

  // Analyst note state
  const [analystNote, setAnalystNote] = useState('');
  const [noteSaving, setNoteSaving] = useState(false);
  const noteSaveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const activeSessionIdRef = useRef<string | null>(null);

  // ── Browser-history navigation ────────────────────────────────────────────
  // navRef mirrors the currently-applied view; navLock suppresses history pushes
  // while a popstate (Back/Forward) is being applied. pushNav records a new view.
  const navRef = useRef<NavState>({ view: 'home' });
  const navLock = useRef(false);
  const pushNav = useCallback((nav: NavState) => {
    if (navLock.current) return;
    history.pushState(nav, '', buildHash(nav));
    navRef.current = nav;
  }, []);

  // Toast state
  const [toasts, setToasts] = useState<Toast[]>([]);

  const showToast = useCallback((message: string, type: Toast['type'] = 'info', opts?: { action?: Toast['action']; duration?: number }) => {
    const id = ++toastCounter;
    setToasts((prev) => [...prev, { id, message, type, action: opts?.action }]);
    // Auto-dismiss (default 4 s; longer for actionable toasts like Undo)
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, opts?.duration ?? 4000);
  }, []);

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Allow WorkflowCanvas to update the result after saving edits
  const handleResultUpdate = useCallback((updatedResult: AnalysisResult) => {
    setResult(updatedResult);
  }, []);

  const loadSessions = useCallback(async (filters?: { search?: string; severity?: string; audience?: string; tags?: string }) => {
    try {
      const list = await api.fetchSessions(filters);
      setSessions(list);
    } catch {
      // Non-critical
    }
  }, []);

  const loadCustomAudiences = useCallback(async () => {
    try {
      const s = await api.fetchSettings();
      const parsed: CustomAudience[] = JSON.parse(s['custom_audiences'] || '[]');
      setCustomAudiences(parsed);
    } catch {
      // Non-critical
    }
  }, []);

  const loadThreatActors = useCallback(async () => {
    try {
      const data = await api.fetchThreatActors();
      setThreatActors(data.actors);
    } catch {
      // Non-critical — threat actors are an optional grouping feature
    }
  }, []);

  const loadAllTags = useCallback(async () => {
    try {
      const tags = await api.fetchAllTags();
      setAllTags(tags);
    } catch {
      // Non-critical
    }
  }, []);

  const loadCases = useCallback(async () => {
    try {
      const data = await api.fetchCases();
      setCases(data.cases);
    } catch {
      // Non-critical — cases are an optional grouping feature
    }
  }, []);

  useEffect(() => {
    loadSessions();
    loadCustomAudiences();
    loadThreatActors();
    loadAllTags();
    loadCases();
  }, [loadSessions, loadCustomAudiences, loadThreatActors, loadAllTags, loadCases]);

  // Keep ref in sync for debounce callback
  useEffect(() => {
    activeSessionIdRef.current = activeSessionId;
  }, [activeSessionId]);

  const handleNoteChange = useCallback((note: string) => {
    setAnalystNote(note);

    // Debounced save
    if (noteSaveTimerRef.current) clearTimeout(noteSaveTimerRef.current);
    noteSaveTimerRef.current = setTimeout(async () => {
      const sid = activeSessionIdRef.current;
      if (!sid) return;
      setNoteSaving(true);
      try {
        await api.saveNote(sid, note);
      } catch {
        // Silently fail — note will be retried on next keystroke
      } finally {
        setNoteSaving(false);
      }
    }, NOTE_DEBOUNCE_MS);
  }, []);

  const handleNewSession = () => {
    pushNav({ view: 'home' });
    setActiveSessionId(null);
    setActiveThreatActorId(null);
    setActiveCaseId(null);
    setSearchOpen(false);
    setIntelOpen(false);
    setResult(null);
    setStreamChunks('');
    setStatusMessage('');
    setError(null);
    setSessionName('');
    setAnalystNote('');
    setSessionTags([]);
    setLinkedThreatActor(null);
    setSessionStatus(null);
    setAnalystOverrides({});
    if (noteSaveTimerRef.current) clearTimeout(noteSaveTimerRef.current);
  };

  const handleSelectSession = async (id: string) => {
    pushNav({ view: 'session', id });
    setActiveSessionId(id);
    setActiveThreatActorId(null);
    setActiveCaseId(null);
    setSearchOpen(false);
    setIntelOpen(false);
    setError(null);
    setAnalystNote('');
    setSessionTags([]);
    setLinkedThreatActor(null);
    if (noteSaveTimerRef.current) clearTimeout(noteSaveTimerRef.current);

    try {
      const data = await api.fetchSession(id);
      // Merge saved analyst overrides into the result so edits persist across sessions
      let loadedResult = data.result;
      if (loadedResult && data.analystOverrides && Object.keys(data.analystOverrides).length > 0) {
        loadedResult = {
          ...loadedResult,
          email_content: { ...loadedResult.email_content, ...data.analystOverrides },
          // Sync incident_summary.severity so the severity dropdown reflects the saved override
          incident_summary: data.analystOverrides['severity_badge']
            ? { ...loadedResult.incident_summary, severity: data.analystOverrides['severity_badge'] as 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' }
            : loadedResult.incident_summary,
        };
      }
      setResult(loadedResult);
      setSessionName(data.session.name);
      setAudience((data.session.audience as AudienceType) ?? 'soc');
      // Load analyst note if the backend returns it
      if (data.note !== undefined) setAnalystNote(data.note ?? '');
      // Load session tags (already parsed by fetchSession)
      setSessionTags(data.session.tags ?? []);
      // Load linked threat actor
      setLinkedThreatActor(data.linked_threat_actor ?? null);
      setSessionStatus((data.session.status as string) ?? null);
      setAnalystOverrides(data.analystOverrides ?? {});
    } catch {
      setError('Failed to load session.');
    }
  };

  // Analyst Workbench — start a blank authored report (original research, no source).
  const handleWriteReport = useCallback(async () => {
    try {
      const name = `Report ${new Date().toISOString().split('T')[0]}`;
      const id = await api.createSession({ name, audience, origin: 'workbench' });
      handleNewSession();
      setActiveSessionId(id);
      setSessionName(name);
      setSessionStatus('pending');
      await loadSessions();
      setWorkbench({ initial: blankResult() });
    } catch {
      showToast('Failed to start a new report', 'error');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [audience, loadSessions, showToast]);

  // Open the Workbench to hand-edit the currently loaded session's result.
  const handleOpenWorkbench = useCallback(() => {
    if (result) setWorkbench({ initial: result });
  }, [result]);

  const handleWorkbenchSaved = useCallback(async () => {
    setWorkbench(null);
    if (activeSessionId) await handleSelectSession(activeSessionId);
    await loadSessions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeSessionId, loadSessions]);

  const handleDeleteSession = useCallback(async (id: string) => {
    try {
      await api.deleteSession(id);
      // If we just deleted the active session, clear the view
      if (activeSessionId === id) {
        setActiveSessionId(null);
        setResult(null);
        setStreamChunks('');
        setStatusMessage('');
        setError(null);
        setSessionName('');
        setAnalystNote('');
      }
      await loadSessions();
      showToast('Session deleted', 'info', {
        duration: 8000,
        action: {
          label: 'Undo',
          onClick: async () => {
            try {
              await api.restoreSession(id);
              await loadSessions();
              showToast('Session restored', 'success');
            } catch {
              showToast('Failed to restore session', 'error');
            }
          },
        },
      });
    } catch {
      showToast('Failed to delete session', 'error');
    }
  }, [activeSessionId, loadSessions, showToast]);

  const handleRestoreSession = useCallback(async (id: string) => {
    await api.restoreSession(id);
    await loadSessions();
    showToast('Session restored', 'success');
  }, [loadSessions, showToast]);

  const handleRenameSession = useCallback(async (id: string, name: string) => {
    try {
      await api.updateSessionName(id, name);
      await loadSessions();
    } catch {
      showToast('Failed to rename session', 'error');
    }
  }, [loadSessions, showToast]);

  const handleBulkDelete = useCallback(async (ids: string[]) => {
    try {
      const result = await api.bulkDeleteSessions(ids);
      // Clear active session if it was deleted
      if (activeSessionId && ids.includes(activeSessionId)) {
        setActiveSessionId(null);
        setResult(null);
        setStreamChunks('');
        setStatusMessage('');
        setError(null);
        setSessionName('');
        setAnalystNote('');
      }
      await loadSessions();
      showToast(`Deleted ${result.deleted} session(s)`, 'info', {
        duration: 8000,
        action: {
          label: 'Undo',
          onClick: async () => {
            try {
              await Promise.all(ids.map((sid) => api.restoreSession(sid).catch(() => {})));
              await loadSessions();
              showToast('Sessions restored', 'success');
            } catch {
              showToast('Failed to restore sessions', 'error');
            }
          },
        },
      });
    } catch {
      showToast('Failed to delete sessions', 'error');
    }
  }, [activeSessionId, loadSessions, showToast]);

  const handleAnalyze = async (params: {
    siemInput: string;
    textInput: string;
    logFile: File | null;
    audience: string;
    redactedStrings: string[];
  }) => {
    setError(null);
    setIsAnalyzing(true);
    setResult(null);
    setStreamChunks('');
    setStreamPhase(1);
    setStatusMessage('Sending to Claude…');
    setAudience(params.audience);
    setAnalystNote('');

    try {
      const userProvidedName = sessionName.trim();
      const name = userProvidedName || `Incident ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`;
      const sid = await api.createSession({ name, audience: params.audience });
      setActiveSessionId(sid);

      await api.streamAnalysis(
        {
          session_id: sid,
          siem_input: params.siemInput || undefined,
          text_input: params.textInput || undefined,
          logFile: params.logFile || undefined,
          audience: params.audience,
          redacted_strings: params.redactedStrings.length > 0 ? params.redactedStrings : undefined,
        },
        (chunk) => setStreamChunks((prev) => prev + chunk),
        (r) => {
          setResult(r);
          setStreamChunks('');
          setStatusMessage('');
          setSessionStatus('complete');
          setAnalystOverrides({});
          // If analyst didn't provide a name, use the AI-generated title
          if (!userProvidedName && r.incident_summary?.title) {
            api.updateSessionName(sid, r.incident_summary.title).catch(() => {});
          }
          showToast('Analysis complete', 'success');
          loadSessions();
          loadThreatActors();
        },
        (err) => {
          setError(`Analysis failed: ${err}`);
          setStreamChunks('');
          setStatusMessage('');
          setSessionStatus('failed');
          showToast(`Analysis failed: ${err}`, 'error');
          loadSessions(); // refresh failed badge in sidebar
        },
        (msg, phase) => {
          setStatusMessage(msg);
          setStreamPhase(phase === 2 ? 2 : 1);
          if (phase === 2) setStreamChunks(''); // clear phase-1 chunks
        }
      );
    } catch (e) {
      const msg = `Failed to start analysis: ${e instanceof Error ? e.message : String(e)}`;
      setError(msg);
      showToast(msg, 'error');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Re-run analysis on the active session using stored inputs (retry on failure
  // or re-analyze with a different audience)
  const handleReanalyze = useCallback(async (audienceOverride?: string) => {
    if (!activeSessionId) return;
    setError(null);
    setIsAnalyzing(true);
    // Keep the existing result visible while re-analyzing so the user retains
    // context; the progress banner shows on top and the result swaps on complete.
    setStreamChunks('');
    setStreamPhase(1);
    setStatusMessage('Re-running analysis — using this session’s stored inputs…');
    if (audienceOverride) setAudience(audienceOverride as AudienceType);
    // Immediate confirmation that the request was sent
    showToast('Re-analysis started — using stored inputs', 'info');

    try {
      await api.streamReanalysis(
        activeSessionId,
        audienceOverride ?? audience,
        (chunk) => setStreamChunks((prev) => prev + chunk),
        (r) => {
          setResult(r);
          setStreamChunks('');
          setStatusMessage('');
          setSessionStatus('complete');
          setAnalystOverrides({});
          showToast('Re-analysis complete', 'success');
          loadSessions();
          loadThreatActors();
        },
        (err) => {
          setError(`Re-analysis failed: ${err}`);
          setStreamChunks('');
          setStatusMessage('');
          setSessionStatus('failed');
          showToast(`Re-analysis failed: ${err}`, 'error');
          loadSessions(); // refresh failed badge
        },
        (msg, phase) => {
          setStatusMessage(msg);
          setStreamPhase(phase === 2 ? 2 : 1);
          if (phase === 2) setStreamChunks('');
        }
      );
    } catch (e) {
      const msg = `Failed to start re-analysis: ${e instanceof Error ? e.message : String(e)}`;
      setError(msg);
      showToast(msg, 'error');
    } finally {
      setIsAnalyzing(false);
    }
  }, [activeSessionId, audience, loadSessions, loadThreatActors, showToast]);

  const handleUpdateTags = useCallback(async (tags: string[]) => {
    if (!activeSessionId) return;
    setSessionTags(tags);
    try {
      const result = await api.updateSessionTags(activeSessionId, tags);
      setSessionTags(result.tags);
      // Refresh session list and tag cloud
      loadSessions();
      loadAllTags();
    } catch {
      showToast('Failed to update tags', 'error');
    }
  }, [activeSessionId, loadSessions, loadAllTags, showToast]);

  const handleUpdateSessionTags = useCallback(async (sessionId: string, tags: string[]) => {
    try {
      const result = await api.updateSessionTags(sessionId, tags);
      // Refresh session list and tag cloud
      loadSessions();
      loadAllTags();
      // If this is the active session, sync its tags
      if (sessionId === activeSessionId) {
        setSessionTags(result.tags);
      }
    } catch {
      showToast('Failed to update tags', 'error');
    }
  }, [activeSessionId, loadSessions, loadAllTags, showToast]);

  // Refresh after threat actor assignment (from WorkflowCanvas or Sidebar)
  const handleActorAssigned = useCallback(async () => {
    loadThreatActors();
    loadSessions();
    // Re-fetch the active session's linked actor
    if (activeSessionId) {
      try {
        const data = await api.fetchSession(activeSessionId);
        setLinkedThreatActor(data.linked_threat_actor ?? null);
      } catch { /* non-critical */ }
    }
  }, [activeSessionId, loadThreatActors, loadSessions]);

  const handleSelectThreatActor = useCallback((id: string) => {
    pushNav({ view: 'actor', id });
    setActiveThreatActorId(id);
    setActiveCaseId(null);
    setActiveSessionId(null);
    setSearchOpen(false);
    setIntelOpen(false);
    setResult(null);
    setStreamChunks('');
    setStatusMessage('');
    setError(null);
    setAnalystNote('');
  }, [pushNav]);

  const handleSelectCase = useCallback((id: string) => {
    pushNav({ view: 'case', id });
    setActiveCaseId(id);
    setActiveThreatActorId(null);
    setActiveSessionId(null);
    setSearchOpen(false);
    setIntelOpen(false);
    setResult(null);
    setStreamChunks('');
    setStatusMessage('');
    setError(null);
    setAnalystNote('');
  }, [pushNav]);

  const handleNewCase = useCallback(async () => {
    const name = window.prompt('New case name:')?.trim();
    if (!name) return;
    try {
      const { case: created } = await api.createCase({ name });
      await loadCases();
      handleSelectCase(created.id);
    } catch {
      showToast('Failed to create case', 'error');
    }
  }, [loadCases, handleSelectCase]);

  const handleOpenSearchView = useCallback((q = '') => {
    pushNav({ view: 'search', seed: q || undefined });
    setSearchSeed(q);
    setSearchOpen(true);
    setIntelOpen(false);
    setSearchPaletteOpen(false);
    setActiveSessionId(null);
    setActiveThreatActorId(null);
    setActiveCaseId(null);
  }, [pushNav]);

  const handleOpenIntel = useCallback(() => {
    pushNav({ view: 'intel' });
    setIntelOpen(true);
    setSearchOpen(false);
    setSearchPaletteOpen(false);
    setActiveSessionId(null);
    setActiveThreatActorId(null);
    setActiveCaseId(null);
  }, [pushNav]);

  // ── Apply a NavState (from popstate / initial load) to the UI ───────────────
  // Latest view handlers, read by applyNav so it doesn't depend on their identity.
  const navHandlersRef = useRef({ handleSelectSession, handleSelectThreatActor, handleSelectCase, handleOpenSearchView, handleOpenIntel, handleNewSession });
  navHandlersRef.current = { handleSelectSession, handleSelectThreatActor, handleSelectCase, handleOpenSearchView, handleOpenIntel, handleNewSession };

  const applyNav = useCallback((nav: NavState) => {
    navLock.current = true;
    try {
      if (!sameView(navRef.current, nav)) {
        const h = navHandlersRef.current;
        switch (nav.view) {
          case 'session': if (nav.id) void h.handleSelectSession(nav.id); break;
          case 'actor':   if (nav.id) h.handleSelectThreatActor(nav.id); break;
          case 'case':    if (nav.id) h.handleSelectCase(nav.id); break;
          case 'search':  h.handleOpenSearchView(nav.seed ?? ''); break;
          case 'intel':   h.handleOpenIntel(); break;
          default:        h.handleNewSession(); break;
        }
      }
      // Modals are part of the nav so Back closes them; open the target, close the rest.
      setSettingsOpen(nav.modal === 'settings');
      setReportsOpen(nav.modal === 'reports');
      setHelpOpen(nav.modal === 'help');
      setChangePasswordOpen(nav.modal === 'changePassword');
      setAdminOpen(nav.modal === 'admin');
      navRef.current = nav;
    } finally {
      navLock.current = false;
    }
  }, []);

  const openModal = useCallback((modal: ModalKind) => {
    const nav: NavState = { ...viewPart(navRef.current), modal };
    history.pushState(nav, '', buildHash(nav));
    navRef.current = nav;
    setSettingsOpen(modal === 'settings');
    setReportsOpen(modal === 'reports');
    setHelpOpen(modal === 'help');
    setChangePasswordOpen(modal === 'changePassword');
    setAdminOpen(modal === 'admin');
  }, []);
  const closeModal = useCallback(() => { history.back(); }, []);

  // Seed history from the URL hash (deep-link) or the default-view pref, and keep
  // React state in sync with the browser Back/Forward buttons.
  useEffect(() => {
    const fromHash = parseHash(window.location.hash);
    const initial: NavState = fromHash.view !== 'home'
      ? fromHash
      : (getDefaultView() === 'intel' ? { view: 'intel' } : { view: 'home' });
    applyNav(initial);
    history.replaceState(initial, '', buildHash(initial));
    navRef.current = initial;
    const onPop = (e: PopStateEvent) => applyNav((e.state as NavState) ?? parseHash(window.location.hash));
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, [applyNav]);

  // ── Cmd/Ctrl+K global search (works even inside inputs) ─────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setSearchPaletteOpen((v) => !v);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  // ── Keyboard shortcuts ──────────────────────────────────────────────────
  useKeyboardShortcuts(
    useMemo(
      () => [
        { key: 'n', description: 'New session', action: handleNewSession },
        { key: '?', shift: true, description: 'Shortcuts help', action: () => setShortcutsOpen((v) => !v) },
        { key: 's', description: 'Toggle sidebar', action: () => setSidebarCollapsed((v) => !v) },
        { key: 'Escape', description: 'Close modals', action: () => {
          if (settingsOpen || reportsOpen || helpOpen || changePasswordOpen || adminOpen) closeModal();
          setShortcutsOpen(false);
        }},
        ...Array.from({ length: 9 }, (_, i) => ({
          key: String(i + 1),
          description: `Select session ${i + 1}`,
          action: () => { if (sessions[i]) handleSelectSession(sessions[i].id); },
        })),
      ],
      [handleNewSession, handleSelectSession, sessions, closeModal, settingsOpen, reportsOpen, helpOpen, changePasswordOpen, adminOpen],
    ),
  );

  return (
    <TooltipProvider>
      <div className="flex h-screen w-screen overflow-hidden bg-background text-foreground">
        <Sidebar
          sessions={sessions}
          activeSessionId={activeSessionId}
          onSelectSession={handleSelectSession}
          onNewSession={handleNewSession}
          onWriteReport={handleWriteReport}
          onOpenSettings={() => openModal('settings')}
          onOpenReports={() => openModal('reports')}
          onOpenHelp={() => openModal('help')}
          onDeleteSession={handleDeleteSession}
          onRenameSession={handleRenameSession}
          loading={isAnalyzing}
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed((v) => !v)}
          onOpenChangePassword={() => openModal('changePassword')}
          onOpenAdmin={() => openModal('admin')}
          onSearchSessions={loadSessions}
          onBulkDelete={handleBulkDelete}
          allTags={allTags}
          activeTagFilters={activeTagFilters}
          onUpdateSessionTags={handleUpdateSessionTags}
          threatActors={threatActors}
          activeThreatActorId={activeThreatActorId}
          onSelectThreatActor={handleSelectThreatActor}
          onClearThreatActor={() => setActiveThreatActorId(null)}
          cases={cases}
          activeCaseId={activeCaseId}
          onSelectCase={handleSelectCase}
          onClearCase={() => setActiveCaseId(null)}
          onNewCase={handleNewCase}
          onOpenSearch={() => handleOpenSearchView()}
          onOpenIntel={handleOpenIntel}
          intelActive={intelOpen}
          onActorAssigned={handleActorAssigned}
        />

        {intelOpen ? (
          <IntelDashboard
            onSelectSession={handleSelectSession}
            onSelectThreatActor={handleSelectThreatActor}
            onOpenSearch={handleOpenSearchView}
          />
        ) : searchOpen ? (
          <SearchView
            initialQuery={searchSeed}
            onSelectSession={handleSelectSession}
            onSelectThreatActor={handleSelectThreatActor}
            onShowToast={showToast}
            onCasesChanged={loadCases}
          />
        ) : activeCaseId ? (
          <CaseView
            key={activeCaseId}
            caseId={activeCaseId}
            onSelectSession={handleSelectSession}
            onSelectThreatActor={handleSelectThreatActor}
            onCaseDeleted={() => { setActiveCaseId(null); loadCases(); }}
            onCaseUpdated={loadCases}
          />
        ) : activeThreatActorId ? (
          <ThreatActorView
            actorId={activeThreatActorId}
            onSelectSession={handleSelectSession}
            onActorDeleted={() => { setActiveThreatActorId(null); loadThreatActors(); }}
            onActorUpdated={loadThreatActors}
            allActors={threatActors}
          />
        ) : (
          <WorkflowCanvas
            result={result}
            isAnalyzing={isAnalyzing}
            streamChunks={streamChunks}
            streamPhase={streamPhase}
            statusMessage={statusMessage}
            sessionName={sessionName}
            onSessionNameChange={setSessionName}
            onAnalyze={handleAnalyze}
            error={error}
            analystNote={analystNote}
            onNoteChange={handleNoteChange}
            noteSaving={noteSaving}
            onRegisterCapture={handleRegisterCapture}
            sessionId={activeSessionId}
            audience={audience}
            onAudienceChange={setAudience}
            onShowToast={showToast}
            captureAttackChain={captureAttackChain}
            customAudiences={customAudiences}
            onResultUpdate={handleResultUpdate}
            onSaveComplete={loadSessions}
            sessionTags={sessionTags}
            allTags={allTags}
            onUpdateTags={handleUpdateTags}
            linkedThreatActor={linkedThreatActor}
            threatActors={threatActors}
            onActorAssigned={handleActorAssigned}
            sessionStatus={sessionStatus}
            onReanalyze={handleReanalyze}
            analystOverrides={analystOverrides}
            onOpenWorkbench={handleOpenWorkbench}
            onSelectSession={handleSelectSession}
            onCasesChanged={loadCases}
          />
        )}

        {workbench && activeSessionId && (
          <Suspense fallback={null}>
            <Workbench
              open
              onClose={() => setWorkbench(null)}
              sessionId={activeSessionId}
              initial={workbench.initial}
              expectedVersion={workbench.version}
              audience={audience}
              onSaved={handleWorkbenchSaved}
              onShowToast={showToast}
            />
          </Suspense>
        )}

        <SettingsModal
          open={settingsOpen}
          onClose={() => { closeModal(); loadCustomAudiences(); }}
          onOpenEmailStudio={() => setBrandingStudioOpen(true)}
        />
        {brandingStudioOpen && (
          <Suspense fallback={null}>
            <EmailStudio
              open={brandingStudioOpen}
              standalone
              onClose={() => setBrandingStudioOpen(false)}
              audience={audience}
              tlp="AMBER"
              onShowToast={showToast}
            />
          </Suspense>
        )}
        <ReportsModal
          open={reportsOpen}
          onClose={() => closeModal()}
          onSelectSession={handleSelectSession}
          onDeleteSession={handleDeleteSession}
          onRestoreSession={handleRestoreSession}
        />
        <HelpModal open={helpOpen} onClose={() => closeModal()} />
        <ChangePasswordModal open={changePasswordOpen} onClose={() => closeModal()} />
        <AdminPanel open={adminOpen} onClose={() => closeModal()} />

        <SearchPalette
          open={searchPaletteOpen}
          onClose={() => setSearchPaletteOpen(false)}
          onSelectSession={handleSelectSession}
          onSelectThreatActor={handleSelectThreatActor}
          onOpenFullSearch={handleOpenSearchView}
        />
        <KeyboardShortcutsOverlay open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
        <ToastContainer toasts={toasts} onDismiss={dismissToast} />
      </div>
    </TooltipProvider>
  );
}

// ── Root component with auth gate ──────────────────────────────────────────

export default function Root() {
  return (
    <AuthProvider>
      <AuthGate />
    </AuthProvider>
  );
}

function AuthGate() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  return <AppMain />;
}
