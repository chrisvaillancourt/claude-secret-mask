export type Mode = 'on' | 'off'

/** The options in plugin.json's userConfig, parsed with defaults filled in. */
export type Config = {
  enabled: boolean
  /** Restore placeholders into Write, Edit and NotebookEdit content. */
  restoreIntoFiles: boolean
  /** Restore placeholders into MCP tool arguments. */
  restoreInMcp: boolean
  /** Refuse an @-mention of a text file that holds a detectable secret, while masking is on. */
  refuseSecretMentions: boolean
  /** The user's patterns file; a leading `~` is the home directory. */
  patternsFile: string
}

/**
 * What the mod keeps in $.state for the session: the on/off override alone.
 * The secret mapping is never here (any plugin can read $.state); it lives in
 * the hooks module's memory.
 */
export type Session = {
  /** A /secret-mask on|off override for this session; null follows the `enabled` option. */
  mode: Mode | null
}

declare module 'claude-code' {
  interface PluginState {
    'secret-mask': { session: Shaped<Session> }
  }
}
