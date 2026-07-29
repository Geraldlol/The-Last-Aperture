/**
 * C-031 — clean fixture. Expected findings at Low or above: ZERO.
 *
 * Why this pattern-matches as vulnerable:
 *   An LWC that reads and writes records, with no Apex FLS check anywhere and no
 *   `Security.stripInaccessible()` in sight. "No CRUD/FLS enforcement" is the
 *   reflex, and there is no Apex in this bundle to point at.
 *
 * Why it is not a finding:
 *   The data path is the Lightning UI API end to end — `getRecord` and
 *   `getFieldValue` from `lightning/uiRecordApi`, `updateRecord` for the write,
 *   and a `lightning-record-edit-form` in the template. The UI API enforces object
 *   permissions, field-level security and sharing SERVER-SIDE, and fields the
 *   running user cannot see are simply absent from the response — so there is no
 *   Apex in the path to add a check to, and adding one would mean routing the data
 *   through custom Apex, which is what would create the gap. This is the
 *   recommended pattern, not a hole in one.
 *
 *   The one thing that IS worth checking on this pattern, and is checked: a
 *   `lightning-record-edit-form` bound to a field the author intended to hide is a
 *   real finding, because FLS is the only control there and hiding a field in
 *   markup is cosmetic. Every field in the template is one the author intends
 *   editable by anyone with FLS on it; the internal-only field
 *   (`Internal_Risk_Note__c`) is bound nowhere in the bundle, and the negative
 *   assertion below is what keeps that true if somebody adds it.
 *
 * False-positive entries exercised:
 *   salesforce-platform (5)  an LWC reading and writing records with no Apex FLS
 *                            check, where the path is the UI API
 */
import { LightningElement, api, wire } from 'lwc';
import { getRecord, getFieldValue, updateRecord } from 'lightning/uiRecordApi';
import { ShowToastEvent } from 'lightning/platformShowToastEvent';

import NAME_FIELD from '@salesforce/schema/Field_Note__c.Name';
import SUMMARY_FIELD from '@salesforce/schema/Field_Note__c.Summary__c';
import STATUS_FIELD from '@salesforce/schema/Field_Note__c.Status__c';
import ID_FIELD from '@salesforce/schema/Field_Note__c.Id';

/**
 * Fields this component reads. A field the running user cannot see is absent from
 * the wire response — the adapter does not error and does not return a masked
 * value, so `getFieldValue` yields undefined and the template renders nothing.
 */
const READ_FIELDS = [NAME_FIELD, SUMMARY_FIELD, STATUS_FIELD];

/**
 * Explicitly NOT bound anywhere in this bundle. Listed so the assertion below has
 * something to check and so a reviewer can see the intent rather than infer it.
 */
const FIELDS_THE_AUTHOR_INTENDS_HIDDEN = ['Internal_Risk_Note__c'];

export default class NoteRecordPanel extends LightningElement {
    @api recordId;

    note;
    error;

    @wire(getRecord, { recordId: '$recordId', fields: READ_FIELDS })
    wiredNote({ data, error }) {
        if (data) {
            this.note = data;
            this.error = undefined;
        } else if (error) {
            this.error = error;
            this.note = undefined;
        }
    }

    get noteName() {
        return getFieldValue(this.note, NAME_FIELD);
    }

    get noteSummary() {
        return getFieldValue(this.note, SUMMARY_FIELD);
    }

    get noteStatus() {
        return getFieldValue(this.note, STATUS_FIELD);
    }

    /**
     * Write through the UI API. Same enforcement as the read: object permissions,
     * FLS and sharing are all applied server-side, and a field the user cannot
     * edit is rejected there rather than here.
     */
    async handleStatusChange(event) {
        const fields = {};
        fields[ID_FIELD.fieldApiName] = this.recordId;
        fields[STATUS_FIELD.fieldApiName] = event.detail.value;

        try {
            await updateRecord({ fields });
            this.dispatchEvent(
                new ShowToastEvent({ title: 'Saved', variant: 'success' })
            );
        } catch (err) {
            // Surfaced, not swallowed. The platform's own message is shown, and it
            // is the FLS/sharing refusal when that is what happened.
            this.dispatchEvent(
                new ShowToastEvent({
                    title: 'Could not save',
                    message: err?.body?.message ?? 'Unknown error',
                    variant: 'error'
                })
            );
        }
    }

    /**
     * Guard for the one real finding on this pattern.
     *
     * A `lightning-record-edit-form` bound to a field the author meant to hide is
     * a finding, because markup-level hiding is cosmetic and FLS is the only
     * control. This runs in the component's own Jest suite and fails if a hidden
     * field ever appears in the rendered form.
     */
    assertNoHiddenFieldIsBound(renderedMarkup) {
        FIELDS_THE_AUTHOR_INTENDS_HIDDEN.forEach((apiName) => {
            if (renderedMarkup.includes(apiName)) {
                throw new Error(
                    `${apiName} is bound in the edit form; hide it with FLS, not markup`
                );
            }
        });
    }
}
