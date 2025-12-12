import mongoose from 'mongoose';
import chalk from 'chalk';
const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGO_URI);
        console.log(chalk.green(`🚀 MongoDB Connected: ${conn.connection.host}`));
        console.log(chalk.blue(`💾 Database Name: ${conn.connection.name}`));
    } catch (error) {
        console.error(chalk.red(`❌ MongoDB Error: ${error.message}`));
        process.exit(1);
    }
};

export default connectDB;
