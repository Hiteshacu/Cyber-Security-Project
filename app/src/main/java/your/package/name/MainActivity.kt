package your.package.name // Make sure this matches your project's package name

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.asRequestBody
import java.io.File
import java.io.IOException

class MainActivity : AppCompatActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var progressBar: ProgressBar
    private lateinit var appAdapter: AppAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        recyclerView = findViewById(R.id.recyclerViewApps)
        progressBar = findViewById(R.id.progressBar)

        recyclerView.layoutManager = LinearLayoutManager(this)
        appAdapter = AppAdapter { appInfo -> 
            // --- Action when an app is clicked --- 
            showToast("Preparing to analyze ${appInfo.name}...")
            uploadApk(appInfo)
        }
        recyclerView.adapter = appAdapter

        loadApps()
    }

    private fun loadApps() {
        progressBar.visibility = View.VISIBLE // Show progress bar while loading
        GlobalScope.launch(Dispatchers.IO) { // Load apps in the background
            val installedApps = getInstalledApps()
            withContext(Dispatchers.Main) {
                appAdapter.updateData(installedApps)
                progressBar.visibility = View.GONE // Hide progress bar when done
            }
        }
    }

    private fun getInstalledApps(): List<AppInfo> {
        val pm: PackageManager = packageManager
        val packages: List<PackageInfo> = try {
            pm.getInstalledPackages(PackageManager.GET_META_DATA)
        } catch (e: Exception) {
            // Handle potential exceptions, e.g., PackageManager has died
            e.printStackTrace()
            emptyList()
        }
        
        val appList = mutableListOf<AppInfo>()

        for (packageInfo in packages) {
            // Filter out system apps
            if ((packageInfo.applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) == 0) {
                try {
                    val appName = packageInfo.applicationInfo.loadLabel(pm).toString()
                    val packageName = packageInfo.packageName
                    val sourceDir = packageInfo.applicationInfo.sourceDir // Path to the APK
                    val icon = packageInfo.applicationInfo.loadIcon(pm)
                    if (sourceDir != null) { // Ensure APK path is valid
                         appList.add(AppInfo(appName, packageName, sourceDir, icon))
                    }
                } catch (e: Exception) {
                    // Handle cases where loading info for a specific package fails
                    println("Failed to load info for package: ${packageInfo.packageName}")
                }
            }
        }
        return appList.sortedBy { it.name.lowercase() } // Sort alphabetically
    }

    // --- Upload Function --- 
    private fun uploadApk(appInfo: AppInfo) {
        // IMPORTANT: Replace with your computer's actual local IP address
        val uploadUrl = "http://192.168.131.90:5001/analyze" 
        val apkFile = File(appInfo.apkPath)

        if (!apkFile.exists()) {
            showToast("Error: APK file not found!")
            println("Error: APK file not found at ${appInfo.apkPath}")
            return
        }

        progressBar.visibility = View.VISIBLE // Show progress during upload

        GlobalScope.launch(Dispatchers.IO) { // Network on background thread
            try {
                val client = OkHttpClient()
                val requestBody: RequestBody = MultipartBody.Builder()
                    .setType(MultipartBody.FORM)
                    .addFormDataPart(
                        "apk_file",
                        apkFile.name, // Use the actual file name
                        apkFile.asRequestBody("application/vnd.android.package-archive".toMediaTypeOrNull())
                    )
                    .build()

                val request: Request = Request.Builder()
                    .url(uploadUrl)
                    .post(requestBody)
                    .build()

                client.newCall(request).execute().use { response ->
                    val responseBody = response.body?.string()
                    if (!response.isSuccessful) throw IOException("Upload failed: ${response.code} ${response.message}\n$responseBody")
                    
                    withContext(Dispatchers.Main) {
                        progressBar.visibility = View.GONE
                        showToast("Analysis complete for ${appInfo.name}!")
                        println("Upload successful: $responseBody")
                        // TODO: Maybe display a summary from responseBody?
                    }
                }
            } catch (e: IOException) {
                 withContext(Dispatchers.Main) {
                    progressBar.visibility = View.GONE
                    showToast("Upload failed: ${e.message}")
                    println("Upload failed: ${e.message}")
                    e.printStackTrace()
                 }
            }
        }
    }
    
    private fun showToast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}

// --- Simple Data Class --- 
data class AppInfo(
    val name: String,
    val packageName: String,
    val apkPath: String,
    val icon: Drawable
)

// --- Basic RecyclerView Adapter --- 
class AppAdapter(private val onItemClicked: (AppInfo) -> Unit) : 
    RecyclerView.Adapter<AppAdapter.AppViewHolder>() {

    private var apps: List<AppInfo> = emptyList()

    // Simple ViewHolder
    class AppViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        // TODO: Find views from list_item_app.xml (e.g., ImageView, TextView)
        val appNameTextView: TextView = view.findViewById(android.R.id.text1) // Example using built-in ID
        // val appIconImageView: ImageView = view.findViewById(R.id.appIcon) // Example if you have R.id.appIcon
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): AppViewHolder {
        // TODO: Inflate your list_item_app.xml layout here
        // Example using a simple built-in layout:
        val view = LayoutInflater.from(parent.context)
            .inflate(android.R.layout.simple_list_item_1, parent, false)
        return AppViewHolder(view)
    }

    override fun onBindViewHolder(holder: AppViewHolder, position: Int) {
        val app = apps[position]
        holder.appNameTextView.text = app.name
        // holder.appIconImageView.setImageDrawable(app.icon) // Set icon if you have an ImageView
        
        holder.itemView.setOnClickListener { 
            onItemClicked(app)
        }
    }

    override fun getItemCount(): Int = apps.size

    fun updateData(newApps: List<AppInfo>) {
        apps = newApps
        notifyDataSetChanged() // Simple way to refresh list, consider DiffUtil for efficiency
    }
}