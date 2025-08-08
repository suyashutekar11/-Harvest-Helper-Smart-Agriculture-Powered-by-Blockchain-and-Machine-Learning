const express = require('express');
const Web3 = require('web3').default;
const path = require('path');

const app = express();
const web3 = new Web3('http://127.0.0.1:7545'); // Connect to Ganache

const contractJSON = require('../build/contracts/CropApplication.json'); // ✅ Correct relative path
const contractABI = contractJSON.abi;
const contractAddress = "0x2787A20520081C1026F53D1FBF6104666c27731F";
const contract = new web3.eth.Contract(contractABI, contractAddress);

const farmerAddress = "0x9a998803ec62ec931a2416cef787a585dcb7cbdb".toLowerCase(); // Farmer's ETH Address

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public')); // For CSS files

// **Fetch Blockchain Events**
async function fetchEvents() {
    try {
        const events = await contract.getPastEvents('allEvents', {
            fromBlock: 0,
            toBlock: 'latest'
        });

        let filteredEvents = events.filter(event => event.returnValues.ethAddress.toLowerCase() === farmerAddress)
            .map(event => ({
                eventName: event.event,
                applicationId: event.returnValues.id,
                timestamp: event.returnValues.timestamp ? new Date(Number(event.returnValues.timestamp.toString()) * 1000).toLocaleString() : "N/A",
                details: event.returnValues
            }));

        return filteredEvents;
    } catch (error) {
        console.error("❌ Error fetching events:", error.message);
        return [];
    }
}

// **Fetch Stored Application Data**
async function fetchStoredData() {
    try {
        const applicationId = await contract.methods.ethToApplicationId(farmerAddress).call();
        if (applicationId === "0x0000000000000000000000000000000000000000000000000000000000000000") {
            return null;
        }

        const application = await contract.methods.cropApplications(applicationId).call();
        return {
            id: application.id,
            status: application.status,
            grade: application.cropGrade || "Not Graded Yet",
            perKgRate: application.perKgRate > 0 ? application.perKgRate + " Rs" : "Not Assigned",
            quantity: application.quantity > 0 ? application.quantity + " KG" : "Not Assigned",
            gradingTimestamp: application.gradingTimestamp > 0 ? new Date(Number(application.gradingTimestamp.toString()) * 1000).toLocaleString() : "Not Graded Yet",
            harvestDate: application.harvestDate > 0 ? new Date(Number(application.harvestDate.toString()) * 1000).toLocaleString() : "Not Booked Yet"
        };
    } catch (error) {
        console.error("❌ Error fetching stored data:", error.message);
        return null;
    }
}

// **Route to Render Web Page**
app.get('/', async (req, res) => {
    const events = await fetchEvents();
    const storedData = await fetchStoredData();
    res.render('index', { events, storedData });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
