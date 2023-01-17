import { useState } from "react";
import { auth, storage, STATE_CHANGED } from "../lib/firebase";
import Loader from "./Loader";

// Uploads images to Firebase Storage
export default function ImageUploader() {
	const [uploading, setUploading] = useState(false); // State to track if the image is uploading
	const [progress, setProgress] = useState(0); // State to track the upload progress as a percentage
	const [downloadURL, setDownloadURL] = useState(null); // State to store the image URL once uploaded

	// Creates a Firebase Upload Task
	const uploadFile = async (e) => {
		// Get the file
		const file = Array.from(e.target.files)[0];
		const extension = file.type.split("/")[1];

		// Make a reference to the storage location
		const ref = storage.ref(
			`uploads/${auth.currentUser.uid}/${Date.now()}.${extension}`
		);
		setUploading(true);

		// Start the upload
		const task = ref.put(file);

		// Listen for state changes, errors, and completion of the upload.
		task.on(STATE_CHANGED, (snapshot) => {
			const pct = (
				(snapshot.bytesTransferred / snapshot.totalBytes) *
				100
			).toFixed(0);
			setProgress(pct);

			// Get downloadURL AFTER task resolves (Note: this is not a native Promise)
			task
				.then((d) => ref.getDownloadURL())
				.then((url) => {
					setDownloadURL(url);
					setUploading(false);
				});
		});
	};

	return (
		<div className="box">
			<Loader show={uploading} />
			{uploading && <h3>{progress}%</h3>}

			{!uploading && (
				<>
					<label className="btn">
						📸 Upload Img
						<input
							type="file"
							onChange={uploadFile}
							accept="image/x-png,image/gif,image/jpeg"
						/>
					</label>
				</>
			)}
			{downloadURL && (
				<code className="upload-snippet">{`![alt](${downloadURL})`}</code>
			)}
		</div>
	);
}
