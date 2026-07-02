export namespace main {
	
	export class ConversationEntry {
	    id: string;
	    from: string;
	    to: string;
	    communicatedAt: string;
	    body: string;
	
	    static createFrom(source: any = {}) {
	        return new ConversationEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.from = source["from"];
	        this.to = source["to"];
	        this.communicatedAt = source["communicatedAt"];
	        this.body = source["body"];
	    }
	}
	export class EncryptedBackup {
	    fileName: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new EncryptedBackup(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fileName = source["fileName"];
	        this.data = source["data"];
	    }
	}
	export class PocFile {
	    id: string;
	    name: string;
	    type: string;
	    size: number;
	    path: string;
	    data: string;
	
	    static createFrom(source: any = {}) {
	        return new PocFile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.size = source["size"];
	        this.path = source["path"];
	        this.data = source["data"];
	    }
	}
	export class Report {
	    id: string;
	    title: string;
	    program: string;
	    asset: string;
	    cvssVersion: string;
	    cvssScore: string;
	    cvssVector: string;
	    status: string;
	    submittedAt: string;
	    nextActionAt: string;
	    rewardStatus: string;
	    rewardAmount: string;
	    rewardCurrency: string;
	    rewardPaidAt: string;
	    rewardNote: string;
	    memo: string;
	    reportUrl: string;
	    maintainerLog: string;
	    conversationLogs: ConversationEntry[];
	    tags: string[];
	    pocFiles: PocFile[];
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
	        this.cvssVersion = source["cvssVersion"];
	        this.cvssScore = source["cvssScore"];
	        this.cvssVector = source["cvssVector"];
	        this.status = source["status"];
	        this.submittedAt = source["submittedAt"];
	        this.nextActionAt = source["nextActionAt"];
	        this.rewardStatus = source["rewardStatus"];
	        this.rewardAmount = source["rewardAmount"];
	        this.rewardCurrency = source["rewardCurrency"];
	        this.rewardPaidAt = source["rewardPaidAt"];
	        this.rewardNote = source["rewardNote"];
	        this.memo = source["memo"];
	        this.reportUrl = source["reportUrl"];
	        this.maintainerLog = source["maintainerLog"];
	        this.conversationLogs = this.convertValues(source["conversationLogs"], ConversationEntry);
	        this.tags = source["tags"];
	        this.pocFiles = this.convertValues(source["pocFiles"], PocFile);
	        this.createdAt = source["createdAt"];
	        this.updatedAt = source["updatedAt"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ReportDraft {
	    id: string;
	    title: string;
	    program: string;
	    asset: string;
	    cvssVersion: string;
	    cvssScore: string;
	    cvssVector: string;
	    status: string;
	    submittedAt: string;
	    nextActionAt: string;
	    rewardStatus: string;
	    rewardAmount: string;
	    rewardCurrency: string;
	    rewardPaidAt: string;
	    rewardNote: string;
	    memo: string;
	    reportUrl: string;
	    maintainerLog: string;
	    conversationLogs: ConversationEntry[];
	    tags: string[];
	    pocFiles: PocFile[];
	
	    static createFrom(source: any = {}) {
	        return new ReportDraft(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.title = source["title"];
	        this.program = source["program"];
	        this.asset = source["asset"];
	        this.cvssVersion = source["cvssVersion"];
	        this.cvssScore = source["cvssScore"];
	        this.cvssVector = source["cvssVector"];
	        this.status = source["status"];
	        this.submittedAt = source["submittedAt"];
	        this.nextActionAt = source["nextActionAt"];
	        this.rewardStatus = source["rewardStatus"];
	        this.rewardAmount = source["rewardAmount"];
	        this.rewardCurrency = source["rewardCurrency"];
	        this.rewardPaidAt = source["rewardPaidAt"];
	        this.rewardNote = source["rewardNote"];
	        this.memo = source["memo"];
	        this.reportUrl = source["reportUrl"];
	        this.maintainerLog = source["maintainerLog"];
	        this.conversationLogs = this.convertValues(source["conversationLogs"], ConversationEntry);
	        this.tags = source["tags"];
	        this.pocFiles = this.convertValues(source["pocFiles"], PocFile);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}
