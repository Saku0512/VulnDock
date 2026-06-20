export namespace main {
	
	export class Report {
	    id: string;
	    title: string;
	    program: string;
	    asset: string;
	    severity: string;
	    status: string;
	    bounty: string;
	    submittedAt: string;
	    dueAt: string;
	    cve: string;
	    tags: string[];
	    summary: string;
	    impact: string;
	    steps: string;
	    evidence: string;
	    notes: string;
	    createdAt: string;
	    updatedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.program = source["program"];
	        this.asset = source["asset"];
	        this.severity = source["severity"];
	        this.status = source["status"];
	        this.bounty = source["bounty"];
	        this.submittedAt = source["submittedAt"];
	        this.dueAt = source["dueAt"];
	        this.cve = source["cve"];
	        this.tags = source["tags"];
	        this.summary = source["summary"];
	        this.impact = source["impact"];
	        this.steps = source["steps"];
	        this.evidence = source["evidence"];
	        this.notes = source["notes"];
	        this.createdAt = source["createdAt"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class ReportDraft {
	    id: string;
	    title: string;
	    program: string;
	    asset: string;
	    severity: string;
	    status: string;
	    bounty: string;
	    submittedAt: string;
	    dueAt: string;
	    cve: string;
	    tags: string[];
	    summary: string;
	    impact: string;
	    steps: string;
	    evidence: string;
	    notes: string;
	
	    static createFrom(source: any = {}) {
	        return new ReportDraft(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.program = source["program"];
	        this.asset = source["asset"];
	        this.severity = source["severity"];
	        this.status = source["status"];
	        this.bounty = source["bounty"];
	        this.submittedAt = source["submittedAt"];
	        this.dueAt = source["dueAt"];
	        this.cve = source["cve"];
	        this.tags = source["tags"];
	        this.summary = source["summary"];
	        this.impact = source["impact"];
	        this.steps = source["steps"];
	        this.evidence = source["evidence"];
	        this.notes = source["notes"];
	    }
	}

}

