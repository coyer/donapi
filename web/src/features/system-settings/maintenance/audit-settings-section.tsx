/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { zodResolver } from '@hookform/resolvers/zod'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import * as z from 'zod'

import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

import {
  SettingsControlGroup,
  SettingsForm,
} from '../components/settings-form-layout'
import { SettingsPageFormActions } from '../components/settings-page-context'
import { SettingsSection } from '../components/settings-section'
import { useResetForm } from '../hooks/use-reset-form'
import { useUpdateOption } from '../hooks/use-update-option'

type AuditMode = 'disabled' | 'local' | 'remote'

const createAuditSchema = () =>
  z.object({
    'audit_setting.mode': z.enum(['disabled', 'local', 'remote']),
    'audit_setting.remote_endpoint': z.string(),
    'audit_setting.remote_timeout': z.coerce.number().int().min(5).max(120),
    'audit_setting.remote_api_key': z.string(),
    'audit_setting.max_file_size': z.coerce.number().int().min(1).max(100),
    'audit_setting.retention_days': z.coerce.number().int().min(1).max(365),
  })

type AuditFormValues = z.infer<ReturnType<typeof createAuditSchema>>

type AuditSettingsSectionProps = {
  defaultValues: AuditFormValues
}

export function AuditSettingsSection({
  defaultValues,
}: AuditSettingsSectionProps) {
  const { t } = useTranslation()
  const updateOption = useUpdateOption()
  const auditSchema = createAuditSchema()

  const form = useForm<AuditFormValues>({
    resolver: zodResolver(auditSchema),
    defaultValues,
  })

  useResetForm(form, defaultValues)

  const mode = form.watch('audit_setting.mode') as AuditMode
  const isLocalMode = mode === 'local'
  const isRemoteMode = mode === 'remote'

  const onSubmit = async (values: AuditFormValues) => {
    const entries = Object.entries(values) as Array<
      [keyof AuditFormValues, AuditFormValues[keyof AuditFormValues]]
    >

    for (const [key, value] of entries) {
      const initial = defaultValues[key]
      if (value === initial) continue

      if (key === 'audit_setting.remote_api_key' && typeof value === 'string') {
        if (!value) continue
      }

      await updateOption.mutateAsync({ key, value })
    }
  }

  return (
    <SettingsSection title={t('Security Audit Settings')}>
      <Alert className='mb-6'>
        <AlertTitle>{t('Security Audit')}</AlertTitle>
        <AlertDescription>
          {t(
            'Security audit records all API requests for security review. Enabling this may increase storage overhead.'
          )}
        </AlertDescription>
      </Alert>

      <Form {...form}>
        <SettingsForm onSubmit={form.handleSubmit(onSubmit)}>
          <SettingsPageFormActions
            onSave={form.handleSubmit(onSubmit)}
            isSaving={updateOption.isPending}
            saveLabel={t('Save Security Audit Settings')}
          />

          <div className='grid gap-6 md:grid-cols-3'>
            <FormField
              control={form.control}
              name='audit_setting.mode'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('Audit Mode')}</FormLabel>
                  <FormControl>
                    <Select
                      value={field.value}
                      onValueChange={(value) =>
                        value !== null && field.onChange(value)
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectGroup>
                          <SelectItem value='disabled'>
                            {t('Disabled (No Logging)')}
                          </SelectItem>
                          <SelectItem value='local'>
                            {t('Local Storage')}
                          </SelectItem>
                          <SelectItem value='remote'>
                            {t('Remote Service')}
                          </SelectItem>
                        </SelectGroup>
                      </SelectContent>
                    </Select>
                  </FormControl>
                  <FormDescription>
                    {t('Where audit records should be stored')}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name='audit_setting.max_file_size'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('Max File Size (MB)')}</FormLabel>
                  <FormControl>
                    <Input
                      type='number'
                      min={1}
                      max={100}
                      {...field}
                      onChange={(event) =>
                        field.onChange(Number(event.target.value))
                      }
                    />
                  </FormControl>
                  <FormDescription>
                    {t(
                      'Maximum individual audit file size before rotation (1-100 MB)'
                    )}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name='audit_setting.retention_days'
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('Log Retention Days')}</FormLabel>
                  <FormControl>
                    <Input
                      type='number'
                      min={1}
                      max={365}
                      {...field}
                      onChange={(event) =>
                        field.onChange(Number(event.target.value))
                      }
                    />
                  </FormControl>
                  <FormDescription>
                    {t(
                      'How many days to keep audit files before cleanup (1-365)'
                    )}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          {isLocalMode && (
            <Alert variant='warning' className='mt-6'>
              <AlertDescription>
                {t(
                  'Local storage mode: Audit logs will be saved to the logs/audit directory, grouped by token and stored by date. Please ensure sufficient disk space.'
                )}
              </AlertDescription>
            </Alert>
          )}

          {isRemoteMode && (
            <SettingsControlGroup className='mt-6 md:grid-cols-2'>
              <FormField
                control={form.control}
                name='audit_setting.remote_endpoint'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('Remote Service URL')}</FormLabel>
                    <FormControl>
                      <Input
                        placeholder='https://audit.example.com'
                        {...field}
                        onChange={(event) => field.onChange(event.target.value)}
                      />
                    </FormControl>
                    <FormDescription>
                      {t('HTTPS endpoint that receives audit records')}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name='audit_setting.remote_timeout'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('Request Timeout (seconds)')}</FormLabel>
                    <FormControl>
                      <Input
                        type='number'
                        min={5}
                        max={120}
                        {...field}
                        onChange={(event) =>
                          field.onChange(Number(event.target.value))
                        }
                      />
                    </FormControl>
                    <FormDescription>
                      {t('Timeout per remote audit request (5-120s)')}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name='audit_setting.remote_api_key'
                render={({ field }) => (
                  <FormItem className='md:col-span-2'>
                    <FormLabel>{t('API Key (Optional)')}</FormLabel>
                    <FormControl>
                      <Input
                        type='password'
                        placeholder='sk-xxx'
                        {...field}
                        onChange={(event) => field.onChange(event.target.value)}
                      />
                    </FormControl>
                    <FormDescription>
                      {t(
                        'Bearer token for authenticating against the remote audit service (leave blank to keep the current value)'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </SettingsControlGroup>
          )}
        </SettingsForm>
      </Form>
    </SettingsSection>
  )
}
