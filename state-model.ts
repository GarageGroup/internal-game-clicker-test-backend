export interface SyncRequestBody {
    token: string | null;
}

export interface GenerateTokenRequestBody {
    data: string;
}

export interface BalanceRequestBody {
    data: {
        amountBalance: string;
        type: string;
    };
}