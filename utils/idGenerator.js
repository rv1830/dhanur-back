import { customAlphabet } from 'nanoid';
const numbers = '0123456789';

export const generateUniquePublicId = async (model, type) => {
    const prefix = type === 'USER' ? 'US' : 'BR';
    const length = type === 'USER' ? 10 : 8;
    const nanoid = customAlphabet(numbers, length);

    let id;
    let isUnique = false;
    
    while (!isUnique) {
        id = `${prefix}-${nanoid()}`;
        // Check if ID already exists in DB
        const query = type === 'USER' ? { uid: id } : { bid: id };
        const exists = await model.findOne(query);
        if (!exists) isUnique = true;
    }
    return id;
};