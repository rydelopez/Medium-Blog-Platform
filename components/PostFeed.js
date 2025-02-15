import Link from "next/link";

export default function PostFeed({ posts, admin }) {
	return posts ? (
		<div>
			{posts.map((post) => (
				<PostItem key={post.slug} post={post} admin={admin} />
			))}
		</div>
	) : null;
}

function PostItem({ post, admin = false }) {
	// Calculate word count and reading time
	const wordCount = post?.content.trim().split(/\s+/g).length;
	const minutesToRead = (wordCount / 100 + 1).toFixed(0);

	return (
		<div className="card">
			<Link href={`/${post.username}`}>
				<strong>By @{post.username}</strong>
			</Link>
			<Link href={`/${post.username}/${post.slug}`}>
				<h2>{post.title}</h2>
			</Link>
			<footer>
				<span>
					{wordCount} words. {minutesToRead} min read
				</span>
				<span className="push-left">❤️ {post.heartCount || 0} Hearts</span>
			</footer>
			{/* If admin view, show extra controls */}
			{admin && (
				<>
					<Link href={`admin/${post.slug}`}>
						<h3>
							<button className="btn-blue">Edit</button>
						</h3>
					</Link>
					{post.published ? (
						<p className="text-success">Live</p>
					) : (
						<p className="text-danger">Unpublished</p>
					)}
				</>
			)}
		</div>
	);
}
