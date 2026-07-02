export type PasswordValidationResult =
  | { ok: true; password: string }
  | { ok: false; errorMessage: string }

export function validateBackupPasswordPair(password: string, confirmPassword: string): PasswordValidationResult {
  if (!password.trim()) {
    return { ok: false, errorMessage: 'バックアップ用パスワードを入力してください。' }
  }
  if (password !== confirmPassword) {
    return { ok: false, errorMessage: 'バックアップ用パスワードが一致しません。' }
  }

  return { ok: true, password }
}

export function validateRestorePassword(password: string): PasswordValidationResult {
  if (!password.trim()) {
    return { ok: false, errorMessage: 'バックアップのパスワードを入力してください。' }
  }

  return { ok: true, password }
}

export function selectedBackupFile(files: FileList | null): File | null {
  return files?.[0] ?? null
}
