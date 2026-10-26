"""MCP 호출 제한과 분리한 감사 검증 작업. 재시작 시 자동 재전송하지 않는다."""
import asyncio
import os
from .audit_verifier import verify_candidates, read_target, grant_path
from .reviews import process_alive
from .workspace import ProductError, ProductStore, now, save_json

TERMINAL = {'COMPLETED','DEFERRED','FAILED','CANCELLED','INTERRUPTED'}


class AuditVerificationJobs:
    def __init__(self,config):
        self.config=config;self.store=ProductStore(config.results);self.tasks={}

    async def start(self,report_id,grant_id):
        read_target(self.config,report_id)
        grant_path(self.config,grant_id)
        identifier=self.store.create('auditjob',{'kind':'audit-verification-job'})
        state={'kind':'audit-verification-job','job_id':identifier,'state':'QUEUED','owner_pid':os.getpid(),
               'reviewed_report_id':report_id,'grant_id':grant_id,'created_at':now(),'report_available':False}
        save_json(self.store.folder(identifier)/'status.json',state)
        task=asyncio.create_task(self._run(identifier,report_id,grant_id))
        self.tasks[identifier]=task
        task.add_done_callback(lambda _:self.tasks.pop(identifier,None))
        return state

    async def _run(self,identifier,report_id,grant_id):
        state=self.store.read(identifier,'status.json')
        state.update(state='RUNNING',updated_at=now());save_json(self.store.folder(identifier)/'status.json',state,replace=True)
        try:
            result=await verify_candidates(self.config,report_id,grant_id)
            final={'COMPLETED_FOR_SELECTED_CANDIDATES':'COMPLETED','DEFERRED':'DEFERRED','INTERRUPTED':'INTERRUPTED'}.get(result['status'],'FAILED')
            report={'kind':'audit-verification-job','report_id':identifier,'result':result,'security_verdict':'NOT_ASSESSED'}
            save_json(self.store.folder(identifier)/'report.json',report)
            state.update(state=final,report_available=True,verification_report_id=result.get('report_id'))
        except asyncio.CancelledError:
            state.update(state='CANCELLED',reason='CANCELLED_NO_AUTOMATIC_RESUME')
        except Exception as error:
            state.update(state='FAILED',reason=str(error) if isinstance(error,ProductError) else type(error).__name__)
        finally:
            state['updated_at']=now();save_json(self.store.folder(identifier)/'status.json',state,replace=True)

    def status(self,identifier):
        state=self.store.read(identifier,'status.json')
        if state.get('kind')!='audit-verification-job':raise ProductError('NOT_AN_AUDIT_VERIFICATION_JOB')
        if state['state'] not in TERMINAL and identifier not in self.tasks and not process_alive(state.get('owner_pid')):
            state.update(state='INTERRUPTED',reason='PROCESS_EXITED_NO_AUTOMATIC_RESUME',updated_at=now())
            save_json(self.store.folder(identifier)/'status.json',state,replace=True)
        return state

    async def cancel(self,identifier):
        self.status(identifier)
        task=self.tasks.get(identifier)
        if task:
            task.cancel()
            try:await task
            except asyncio.CancelledError:pass
            state=self.store.read(identifier,'status.json')
            if state['state'] in {'QUEUED','INTERRUPTED'}:
                state.update(state='CANCELLED',updated_at=now())
                save_json(self.store.folder(identifier)/'status.json',state,replace=True)
        return self.status(identifier)
