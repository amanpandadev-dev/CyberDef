const IST_ZONE = 'Asia/Kolkata';

export const formatISTDateTime = (value: string | Date): string => {
    const date = value instanceof Date ? value : new Date(value);
    const formatted = new Intl.DateTimeFormat('en-GB', {
        timeZone: IST_ZONE,
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
    }).format(date);
    return `${formatted.replace(',', '')} IST`;
};

export const formatISTDate = (value: string | Date): string => {
    const date = value instanceof Date ? value : new Date(value);
    return new Intl.DateTimeFormat('en-GB', {
        timeZone: IST_ZONE,
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
    }).format(date);
};

export const toISTDateKey = (value: string | Date): string => {
    return formatISTDate(value);
};
